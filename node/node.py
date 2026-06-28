#!/usr/bin/env python3
import errno
import fcntl
import html
import json
import os
import re
import signal
import ssl
import threading
import sys
import tempfile
import time
from collections import OrderedDict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs

try:
    import requests  # type: ignore
except Exception:
    requests = None

import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

WORK_DIR = Path(os.environ.get("NODE_WORK_DIR", "/root/node"))
CONFIG_FILE = WORK_DIR / "node_config.txt"
LOG_FILE = WORK_DIR / "node.log"
CRON_LOG = WORK_DIR / "node_cron.log"
BOOT_LOG = WORK_DIR / "node_boot.log"
WEB_LOG = WORK_DIR / "node_web.log"
STATE_JSON = WORK_DIR / "node_state.json"
LAST_NODE_TXT = WORK_DIR / "last_node.txt"
CACHE_JSON = WORK_DIR / ".node_http_cache.json"
RSS_LOG_JSON = WORK_DIR / "node_rss_log.json"
PID_FILE = WORK_DIR / ".node_python.pid"
LOCK_FILE = WORK_DIR / ".node_python.lock"
WEB_PID_FILE = WORK_DIR / ".node_keyword_web.pid"
WEB_LOCK_FILE = WORK_DIR / ".node_keyword_web.lock"
LOG_RESET_FILE = WORK_DIR / ".log_last_reset_day"
RUN_ENABLED_FILE = WORK_DIR / ".node_run_enabled"
WEB_RESTART_FILE = WORK_DIR / ".node_web_restart"

DEFAULT_URL = "https://rss.nodeseek.com/?sortBy=postTime"
DEFAULT_WEB_HOST = os.environ.get("NODE_WEB_HOST", "0.0.0.0")
DEFAULT_WEB_PORT = int(os.environ.get("NODE_WEB_PORT", "2068"))
DEFAULT_WEB_PIN = os.environ.get("NODE_WEB_PIN", "0819")
LETSENCRYPT_LIVE = Path("/etc/letsencrypt/live")
MAX_STATE_ENTRIES = 30
MAX_RSS_LOG_ENTRIES = 120
MATCH_WINDOW = 30
MANUAL_PUSH_WINDOW = 20
HTTP_TIMEOUT = 10
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36"
)
KEY_RE = re.compile(r'^(\s*KEYWORDS\s*=\s*")(.*?)("\s*)$')


def ensure_workdir() -> None:
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    for p in (LOG_FILE, CRON_LOG, BOOT_LOG, WEB_LOG):
        if not p.exists():
            p.touch()


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def fmt_time() -> str:
    return datetime.now().strftime("%Y.%m.%d.%H:%M")


def is_run_enabled() -> bool:
    """网页运行开关。默认开启；关闭后仅暂停自动监控/推送，网页本身保持可访问。"""
    try:
        if not RUN_ENABLED_FILE.exists():
            return True
        value = RUN_ENABLED_FILE.read_text(encoding="utf-8").strip().lower()
        return value not in {"0", "false", "off", "stop", "stopped", "disabled"}
    except Exception:
        return True


def set_run_enabled(enabled: bool) -> None:
    ensure_workdir()
    RUN_ENABLED_FILE.write_text("1" if enabled else "0", encoding="utf-8")


class Logger:
    def __init__(self, debug: bool = False):
        self.debug = debug

    def _write(self, path: Path, message: str) -> None:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(f"{now_str()} {message}\n")

    def info(self, message: str) -> None:
        if self.debug:
            self._write(LOG_FILE, message)

    def event(self, message: str) -> None:
        self._write(CRON_LOG, message)

    def error(self, message: str) -> None:
        self._write(LOG_FILE, message)


def parse_shell_config(path: Path) -> Dict[str, str]:
    data: Dict[str, str] = {}
    if not path.exists() or path.stat().st_size == 0:
        return data
    pattern = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
    with path.open("r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            m = pattern.match(line)
            if not m:
                continue
            key, raw_val = m.group(1), m.group(2).strip()
            if len(raw_val) >= 2 and raw_val[0] == raw_val[-1] and raw_val[0] in {'"', "'"}:
                val = raw_val[1:-1]
                val = val.replace(r'\"', '"').replace(r"\\", "\\")
            else:
                val = raw_val
            data[key] = val
    return data


def load_runtime_config() -> Dict[str, str]:
    cfg = parse_shell_config(CONFIG_FILE)
    cfg.setdefault("NS_URL", DEFAULT_URL)
    cfg.setdefault("INTERVAL_SEC", "15")
    cfg.setdefault("KEYWORDS", "")
    cfg.setdefault("DEBUG_LOG", "0")
    cfg.setdefault("WEB_HOST", DEFAULT_WEB_HOST)
    cfg.setdefault("WEB_PORT", str(DEFAULT_WEB_PORT))
    cfg.setdefault("WEB_PIN", DEFAULT_WEB_PIN)
    cfg.setdefault("WEB_DOMAIN", "")
    cfg.setdefault("PUSH_CHANNEL", "tg")
    cfg.setdefault("NTFY_URL", "http://127.0.0.1:8083")
    cfg.setdefault("NTFY_USERNAME", "")
    cfg.setdefault("NTFY_PASSWORD", "")
    cfg.setdefault("NTFY_TOPIC", "node")
    cfg.setdefault("NTFY_PRIORITY", "3")
    return cfg


def normalize_push_channel(cfg: Dict[str, str]) -> str:
    channel = (cfg.get("PUSH_CHANNEL", "tg") or "tg").strip().lower()
    if channel in {"telegram", "tg"}:
        return "tg"
    if channel == "ntfy":
        return "ntfy"
    # 配置异常时优先根据已有 ntfy 参数自愈，避免误判成 Telegram。
    if cfg.get("NTFY_URL") or cfg.get("NTFY_TOPIC"):
        return "ntfy"
    return "tg"


def validate_config(cfg: Dict[str, str]) -> Tuple[bool, str]:
    channel = normalize_push_channel(cfg)

    required = ["NS_URL"]
    if channel == "tg":
        required.extend(["TG_BOT_TOKEN", "TG_PUSH_CHAT_ID"])
    elif channel == "ntfy":
        required.extend(["NTFY_URL", "NTFY_TOPIC"])

    for key in required:
        if not cfg.get(key):
            return False, f"配置不完整，缺少 {key}"
    try:
        interval = int(cfg.get("INTERVAL_SEC", "20"))
    except ValueError:
        return False, "INTERVAL_SEC 必须是数字"
    if interval < 15:
        return False, "INTERVAL_SEC 最低 15"
    return True, ""

def safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def escape_shell_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", " ")


def unescape_shell_value(value: str) -> str:
    out: List[str] = []
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value):
            out.append(value[i + 1])
            i += 2
        else:
            out.append(value[i])
            i += 1
    return "".join(out)


def read_keywords() -> str:
    if not CONFIG_FILE.exists():
        return ""
    with CONFIG_FILE.open("r", encoding="utf-8") as fh:
        for raw in fh:
            m = KEY_RE.match(raw.rstrip("\n"))
            if m:
                return unescape_shell_value(m.group(2))
    return ""


def update_keywords(new_value: str) -> None:
    new_value = escape_shell_value(new_value)
    lines: List[str] = []
    found = False

    if CONFIG_FILE.exists():
        with CONFIG_FILE.open("r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.rstrip("\n")
                m = KEY_RE.match(line)
                if m and not found:
                    lines.append(f'{m.group(1)}{new_value}{m.group(3)}')
                    found = True
                else:
                    lines.append(line)

    if not found:
        lines.append(f'KEYWORDS="{new_value}"')

    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="node_config.", dir=str(CONFIG_FILE.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        os.replace(tmp_path, CONFIG_FILE)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def keyword_web_settings(cfg: Dict[str, str]) -> Dict[str, str]:
    host = (cfg.get("WEB_HOST", DEFAULT_WEB_HOST) or DEFAULT_WEB_HOST).strip() or DEFAULT_WEB_HOST
    port = safe_int(cfg.get("WEB_PORT", str(DEFAULT_WEB_PORT)), DEFAULT_WEB_PORT)
    if port <= 0 or port > 65535:
        port = DEFAULT_WEB_PORT
    pin = (cfg.get("WEB_PIN", DEFAULT_WEB_PIN) or DEFAULT_WEB_PIN).strip()
    if not re.fullmatch(r"\d{4}", pin):
        pin = DEFAULT_WEB_PIN
    domain = (cfg.get("WEB_DOMAIN", "") or "").strip()
    cert_path = ""
    key_path = ""
    scheme = "http"
    bind_name = domain or host
    if domain:
        cert = LETSENCRYPT_LIVE / domain / "fullchain.pem"
        key = LETSENCRYPT_LIVE / domain / "privkey.pem"
        if cert.is_file() and key.is_file():
            cert_path = str(cert)
            key_path = str(key)
            scheme = "https"
    return {
        "host": host,
        "port": str(port),
        "pin": pin,
        "domain": domain,
        "ssl_cert": cert_path,
        "ssl_key": key_path,
        "scheme": scheme,
        "url": f"{scheme}://{bind_name}:{port}",
    }


class Transport:
    def get(self, url: str, headers: Dict[str, str], timeout: int):
        raise NotImplementedError

    def post_form(self, url: str, data: Dict[str, str], timeout: int):
        raise NotImplementedError


class RequestsTransport(Transport):
    def __init__(self):
        self.session = requests.Session()  # type: ignore[union-attr]
        adapter = requests.adapters.HTTPAdapter(pool_connections=2, pool_maxsize=4)  # type: ignore[attr-defined]
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def get(self, url: str, headers: Dict[str, str], timeout: int):
        resp = self.session.get(url, headers=headers, timeout=timeout)
        return resp.status_code, dict(resp.headers), resp.content

    def post_form(self, url: str, data: Dict[str, str], timeout: int):
        resp = self.session.post(url, data=data, timeout=timeout)
        return resp.status_code, dict(resp.headers), resp.content


class UrllibTransport(Transport):
    def __init__(self):
        self.opener = urllib.request.build_opener()

    def get(self, url: str, headers: Dict[str, str], timeout: int):
        req = urllib.request.Request(url=url, headers=headers, method="GET")
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                return resp.getcode(), dict(resp.headers.items()), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers.items()) if exc.headers else {}, exc.read()

    def post_form(self, url: str, data: Dict[str, str], timeout: int):
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(url=url, data=encoded, method="POST")
        with self.opener.open(req, timeout=timeout) as resp:
            return resp.getcode(), dict(resp.headers.items()), resp.read()


def build_transport() -> Transport:
    if requests is not None:
        return RequestsTransport()
    return UrllibTransport()


class KeywordMatcher:
    def __init__(self, raw_keywords: str):
        # 支持两种写法：
        # 1) 单关键词：a
        # 2) 多关键词同时匹配：a&b 或 a&b&c，只有标题同时包含所有片段才命中
        self.tokens: List[Tuple[str, ...]] = []
        raw_keywords = raw_keywords.replace(",", " ")
        for token in raw_keywords.split():
            token = token.strip().lower()
            if not token:
                continue
            compact = token.replace(" ", "")
            parts = tuple(part for part in compact.split("&") if part)
            if parts:
                self.tokens.append(parts)

    def match(self, title: str) -> str:
        if not self.tokens:
            return ""
        t = title.lower()
        for parts in self.tokens:
            if all(part in t for part in parts):
                return "&".join(parts)
        return ""


class StateStore:
    def __init__(self):
        self.entries: "OrderedDict[str, Dict[str, object]]" = OrderedDict()

    @staticmethod
    def _sort_key(entry: Dict[str, object]) -> Tuple[int, int, str]:
        id_str = str(entry.get("id", ""))
        if id_str.isdigit():
            return (0, int(id_str), id_str)
        nums = re.findall(r"\d+", id_str)
        if nums:
            return (0, int(nums[-1]), id_str)
        return (1, 0, id_str)

    def load(self) -> None:
        self.entries = OrderedDict()
        if STATE_JSON.exists() and STATE_JSON.stat().st_size > 0:
            with STATE_JSON.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
            for item in raw.get("entries", []):
                entry = {
                    "id": str(item.get("id", "")),
                    "title": str(item.get("title", "")),
                    "url": str(item.get("url", "")),
                    "sent": bool(item.get("sent", False)),
                    "seen_at": str(item.get("seen_at", "")),
                }
                if entry["id"]:
                    self.entries[entry["id"]] = entry
            self._normalize()
            return

        if LAST_NODE_TXT.exists() and LAST_NODE_TXT.stat().st_size > 0:
            with LAST_NODE_TXT.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    parts = line.split("|", 3)
                    if len(parts) < 3:
                        continue
                    id_, title, url = parts[0], parts[1], parts[2]
                    sent = len(parts) >= 4 and parts[3] == "1"
                    self.entries[id_] = {
                        "id": id_,
                        "title": title,
                        "url": url,
                        "sent": sent,
                        "seen_at": "",
                    }
            self._normalize()
            self.save()

    def _normalize(self) -> None:
        items = sorted(self.entries.values(), key=self._sort_key)
        if len(items) > MAX_STATE_ENTRIES:
            items = items[-MAX_STATE_ENTRIES:]
        self.entries = OrderedDict((str(item["id"]), item) for item in items)

    def save(self) -> None:
        self._normalize()
        payload = {"entries": list(self.entries.values())}
        tmp = STATE_JSON.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        tmp.replace(STATE_JSON)
        self.export_last_node_txt()

    def export_last_node_txt(self) -> None:
        tmp = LAST_NODE_TXT.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for entry in self.entries.values():
                sent = "1" if entry.get("sent") else "0"
                fh.write(f"{entry['id']}|{entry['title']}|{entry['url']}|{sent}\n")
        tmp.replace(LAST_NODE_TXT)

    def merge_posts(self, posts: List[Dict[str, str]]) -> int:
        changes = 0
        now_value = now_str()
        for post in posts:
            old = self.entries.get(post["id"])
            if old is None:
                self.entries[post["id"]] = {
                    "id": post["id"],
                    "title": post["title"],
                    "url": post["url"],
                    "sent": False,
                    "seen_at": now_value,
                }
                changes += 1
                continue
            if old.get("title") != post["title"] or old.get("url") != post["url"]:
                old["title"] = post["title"]
                old["url"] = post["url"]
                changes += 1
        self._normalize()
        return changes

    def latest_entries(self, limit: int) -> List[Dict[str, object]]:
        return list(self.entries.values())[-limit:]


class NodeMonitor:
    def __init__(self):
        ensure_workdir()
        self.transport = build_transport()
        self.cache = self._load_cache()
        self.logger = Logger(False)
        self.config = load_runtime_config()
        self.state = StateStore()
        self.state.load()

    def reload_config(self) -> None:
        self.config = load_runtime_config()
        self.logger.debug = self.config.get("DEBUG_LOG", "0") == "1"

    def _load_cache(self) -> Dict[str, str]:
        if CACHE_JSON.exists() and CACHE_JSON.stat().st_size > 0:
            try:
                with CACHE_JSON.open("r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                return {"last_modified": str(raw.get("last_modified", "")), "etag": str(raw.get("etag", ""))}
            except Exception:
                return {"last_modified": "", "etag": ""}
        return {"last_modified": "", "etag": ""}

    def _save_cache(self) -> None:
        tmp = CACHE_JSON.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(self.cache, fh, ensure_ascii=False, indent=2)
        tmp.replace(CACHE_JSON)

    def _http_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Connection": "keep-alive",
        }
        if self.cache.get("last_modified"):
            headers["If-Modified-Since"] = self.cache["last_modified"]
        if self.cache.get("etag"):
            headers["If-None-Match"] = self.cache["etag"]
        return headers

    def fetch_rss(self) -> Tuple[str, Optional[bytes]]:
        url = self.config.get("NS_URL", DEFAULT_URL)
        try:
            code, headers, body = self.transport.get(url, self._http_headers(), HTTP_TIMEOUT)
        except Exception as exc:
            self.logger.error(f"[node] RSS请求异常: {exc}")
            return "error", None

        if code == 304:
            self.logger.info("[node] RSS未更新（304）")
            return "not_modified", None

        if code != 200:
            self.logger.error(f"[node] RSS请求失败 HTTP={code}")
            return "error", None

        lm = headers.get("Last-Modified") or headers.get("last-modified")
        etag = headers.get("ETag") or headers.get("etag")
        if lm:
            self.cache["last_modified"] = lm.strip()
        if etag:
            self.cache["etag"] = etag.strip()
        self._save_cache()
        return "ok", body

    @staticmethod
    def _local_name(tag: str) -> str:
        if "}" in tag:
            return tag.rsplit("}", 1)[1]
        return tag

    def parse_posts(self, payload: bytes) -> Tuple[str, List[Dict[str, str]]]:
        text_sample = payload[:5120].decode("utf-8", errors="ignore")
        if re.search(r"Just a moment|cf-turnstile|challenge-platform|captcha", text_sample, flags=re.I):
            return "blocked", []
        try:
            root = ET.fromstring(payload)
        except ET.ParseError as exc:
            self.logger.error(f"[node] RSS解析失败: {exc}")
            return "error", []

        posts: List[Dict[str, str]] = []
        for elem in root.iter():
            if self._local_name(elem.tag) != "item":
                continue
            title = ""
            link = ""
            guid = ""
            for child in list(elem):
                name = self._local_name(child.tag)
                text = (child.text or "").strip()
                if name == "title":
                    title = html.unescape(text)
                elif name == "link":
                    link = text
                elif name == "guid":
                    guid = text
            id_ = guid if guid.isdigit() else ""
            if not id_:
                m = re.search(r"post-(\d+)-1", link)
                if m:
                    id_ = m.group(1)
            if id_ and title and link:
                posts.append({"id": id_, "title": title, "url": link})
            if len(posts) >= 120:
                break
        if not posts:
            return "empty", []
        return "ok", posts

    def telegram_send(self, content: str) -> bool:
        token = self.config.get("TG_BOT_TOKEN", "")
        chat_id = self.config.get("TG_PUSH_CHAT_ID", "")
        if not token or not chat_id:
            self.logger.error("[node] Telegram配置缺失，发送失败")
            return False
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = {
            "chat_id": chat_id,
            "text": content,
            "disable_web_page_preview": "true",
        }
        try:
            code, _, body = self.transport.post_form(url, data, HTTP_TIMEOUT)
            if code != 200:
                self.logger.error(f"[node] Telegram发送失败 HTTP={code}")
                return False
            if body:
                try:
                    payload = json.loads(body.decode("utf-8", errors="ignore"))
                    if payload.get("ok") is False:
                        self.logger.error(f"[node] Telegram返回失败: {payload}")
                        return False
                except Exception:
                    pass
            return True
        except Exception as exc:
            self.logger.error(f"[node] Telegram发送异常: {exc}")
            return False

    def ntfy_send(self, content: str) -> bool:
        url = (self.config.get("NTFY_URL", "http://127.0.0.1:8083") or "http://127.0.0.1:8083").rstrip("/")
        topic = (self.config.get("NTFY_TOPIC", "node") or "node").strip().strip("/")
        username = self.config.get("NTFY_USERNAME", "")
        password = self.config.get("NTFY_PASSWORD", "")
        priority = (self.config.get("NTFY_PRIORITY", "3") or "3").strip()
        if priority not in {"1", "2", "3", "4", "5"}:
            priority = "3"
        if not url or not topic:
            self.logger.error("[node] ntfy配置缺失，发送失败")
            return False
        target = f"{url}/{urllib.parse.quote(topic)}"
        headers = {
            "Priority": priority,
            "Content-Type": "text/plain; charset=utf-8",
        }
        data = content.encode("utf-8")
        try:
            if requests is not None:
                kwargs = {"headers": headers, "data": data, "timeout": HTTP_TIMEOUT}
                if username or password:
                    kwargs["auth"] = (username, password)
                resp = requests.post(target, **kwargs)  # type: ignore[arg-type]
                if 200 <= resp.status_code < 300:
                    return True
                self.logger.error(f"[node] ntfy发送失败 HTTP={resp.status_code} resp={resp.text[:500]}")
                return False

            req = urllib.request.Request(url=target, data=data, headers=headers, method="POST")
            if username or password:
                token = (f"{username}:{password}").encode("utf-8")
                import base64
                req.add_header("Authorization", "Basic " + base64.b64encode(token).decode("ascii"))
            try:
                with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                    code = resp.getcode()
                    return 200 <= code < 300
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="ignore")[:500]
                self.logger.error(f"[node] ntfy发送失败 HTTP={exc.code} resp={body}")
                return False
        except Exception as exc:
            self.logger.error(f"[node] ntfy发送异常: {exc}")
            return False

    def send_message(self, content: str) -> bool:
        channel = normalize_push_channel(self.config)
        if channel == "ntfy":
            return self.ntfy_send(content)
        return self.telegram_send(content)


    def _load_rss_log_data(self) -> Dict[str, List[Dict[str, object]]]:
        """读取 RSS 日志。新版分为 all_logs 和 hit_logs；自动兼容旧版 logs/list。"""
        data: Dict[str, List[Dict[str, object]]] = {"all_logs": [], "hit_logs": []}
        if RSS_LOG_JSON.exists() and RSS_LOG_JSON.stat().st_size > 0:
            try:
                with RSS_LOG_JSON.open("r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                if isinstance(raw, dict) and ("all_logs" in raw or "hit_logs" in raw):
                    all_logs = raw.get("all_logs", [])
                    hit_logs = raw.get("hit_logs", [])
                    if isinstance(all_logs, list):
                        data["all_logs"] = [item for item in all_logs if isinstance(item, dict)]
                    if isinstance(hit_logs, list):
                        data["hit_logs"] = [item for item in hit_logs if isinstance(item, dict)]
                    return data

                old_logs = raw.get("logs", raw if isinstance(raw, list) else []) if isinstance(raw, dict) else raw
                if isinstance(old_logs, list):
                    clean = [item for item in old_logs if isinstance(item, dict)]
                    data["all_logs"] = clean
                    data["hit_logs"] = [dict(item) for item in clean if item.get("matched")]
            except Exception as exc:
                self.logger.error(f"[node] RSS日志读取失败: {exc}")
        return data

    def _save_rss_log_data(self, data: Dict[str, List[Dict[str, object]]]) -> None:
        tmp = RSS_LOG_JSON.with_suffix(".tmp")
        payload = {
            "all_logs": list(data.get("all_logs", []))[:MAX_RSS_LOG_ENTRIES],
            "hit_logs": list(data.get("hit_logs", []))[:MAX_RSS_LOG_ENTRIES],
        }
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        tmp.replace(RSS_LOG_JSON)

    def _push_status_for_id(self, id_: str, fallback_sent: bool = False, fallback_status: str = "") -> Tuple[bool, str]:
        entry = self.state.entries.get(str(id_), {})
        sent = bool(entry.get("sent", fallback_sent))
        if sent:
            return True, "已推送"
        if fallback_status == "推送失败":
            return False, "推送失败"
        return False, "未推送"

    def _upsert_front(self, rows: List[Dict[str, object]], row: Dict[str, object], key: str = "id") -> List[Dict[str, object]]:
        row_id = str(row.get(key, ""))
        rest = [item for item in rows if str(item.get(key, "")) != row_id]
        return [row] + rest

    def append_rss_logs(self, posts: List[Dict[str, str]]) -> None:
        """记录 RSS 全部日志和独立命中日志。命中日志不会被 RSS 全部滚动挤掉。"""
        self.reload_config()
        matcher = KeywordMatcher(self.config.get("KEYWORDS", ""))
        now_value = now_str()
        data = self._load_rss_log_data()
        all_logs = data.get("all_logs", [])
        hit_logs = data.get("hit_logs", [])
        all_by_id = {str(item.get("id", "")): item for item in all_logs if item.get("id")}
        hit_by_id = {str(item.get("id", "")): item for item in hit_logs if item.get("id")}

        seen_ids = set()
        new_all: List[Dict[str, object]] = []
        new_hit_logs = list(hit_logs)

        for post in posts:
            id_ = str(post.get("id", ""))
            if not id_ or id_ in seen_ids:
                continue
            seen_ids.add(id_)
            title = str(post.get("title", ""))
            url = str(post.get("url", ""))
            hit = matcher.match(title)
            old_all = all_by_id.get(id_, {})
            old_hit = hit_by_id.get(id_, {})
            sent, push_status = self._push_status_for_id(
                id_,
                fallback_sent=bool(old_hit.get("sent", old_all.get("sent", False))),
                fallback_status=str(old_hit.get("push_status", old_all.get("push_status", ""))),
            )
            row = {
                "id": id_,
                "title": title,
                "url": url,
                "matched": bool(hit),
                "hit": hit,
                "sent": sent,
                "push_status": push_status if hit else "",
                "checked_at": now_value,
                "first_seen_at": str(old_all.get("first_seen_at") or now_value),
            }
            new_all.append(row)

            if hit:
                hit_row = dict(old_hit) if old_hit else {}
                hit_row.update(row)
                hit_row["matched_at"] = str(old_hit.get("matched_at") or now_value)
                hit_row["checked_at"] = now_value
                new_hit_logs = self._upsert_front(new_hit_logs, hit_row)

        for item in all_logs:
            id_ = str(item.get("id", ""))
            if id_ and id_ not in seen_ids:
                new_all.append(item)
            if len(new_all) >= MAX_RSS_LOG_ENTRIES:
                break

        data["all_logs"] = new_all[:MAX_RSS_LOG_ENTRIES]
        data["hit_logs"] = new_hit_logs[:MAX_RSS_LOG_ENTRIES]
        self._save_rss_log_data(data)

    def get_rss_logs(self, mode: str = "all", limit: int = 20) -> List[Dict[str, object]]:
        self.reload_config()
        matcher = KeywordMatcher(self.config.get("KEYWORDS", ""))
        data = self._load_rss_log_data()

        if not data.get("all_logs"):
            # 兼容首次升级：从状态缓存生成 RSS 全部日志，并同步生成命中日志。
            all_logs: List[Dict[str, object]] = []
            hit_logs: List[Dict[str, object]] = []
            for entry in reversed(self.state.latest_entries(MAX_RSS_LOG_ENTRIES)):
                id_ = str(entry.get("id", ""))
                title = str(entry.get("title", ""))
                hit = matcher.match(title)
                sent, push_status = self._push_status_for_id(id_, fallback_sent=bool(entry.get("sent", False)))
                row = {
                    "id": id_,
                    "title": title,
                    "url": str(entry.get("url", "")),
                    "matched": bool(hit),
                    "hit": hit,
                    "sent": sent,
                    "push_status": push_status if hit else "",
                    "checked_at": str(entry.get("seen_at") or now_str()),
                    "first_seen_at": str(entry.get("seen_at") or ""),
                }
                all_logs.append(row)
                if hit:
                    hit_row = dict(row)
                    hit_row["matched_at"] = str(entry.get("seen_at") or now_str())
                    hit_logs.append(hit_row)
            data = {"all_logs": all_logs, "hit_logs": hit_logs}
            self._save_rss_log_data(data)

        rows = list(data.get("hit_logs" if mode in {"hit", "hits", "matched"} else "all_logs", []))

        normalized: List[Dict[str, object]] = []
        for item in rows:
            row = dict(item)
            title = str(row.get("title", ""))
            hit = matcher.match(title)
            row["matched"] = bool(hit)
            row["hit"] = hit
            sent, push_status = self._push_status_for_id(
                str(row.get("id", "")),
                fallback_sent=bool(row.get("sent", False)),
                fallback_status=str(row.get("push_status", "")),
            )
            row["sent"] = sent
            row["push_status"] = push_status if row.get("matched") else ""
            normalized.append(row)

        if mode in {"hit", "hits", "matched"}:
            normalized = [item for item in normalized if item.get("matched")]
        return normalized[:max(1, min(limit, 100))]

    def clear_rss_logs(self) -> None:
        self._save_rss_log_data({"all_logs": [], "hit_logs": []})

    def _update_rss_push_status(self, ids: List[str], status: str) -> None:
        if not ids:
            return
        id_set = {str(x) for x in ids if str(x)}
        if not id_set:
            return
        data = self._load_rss_log_data()
        now_value = now_str()
        sent_value = status == "已推送"
        for bucket in ("all_logs", "hit_logs"):
            for row in data.get(bucket, []):
                if str(row.get("id", "")) in id_set:
                    row["sent"] = sent_value
                    row["push_status"] = status if row.get("matched") or bucket == "hit_logs" else ""
                    row["last_push_at"] = now_value
        self._save_rss_log_data(data)

    def _pending_hit_log_matches(self, exclude_ids: Optional[set] = None) -> Tuple[List[str], List[str]]:
        """返回命中日志中未推送/推送失败的记录，用于自动补推。"""
        exclude_ids = exclude_ids or set()
        self.reload_config()
        matcher = KeywordMatcher(self.config.get("KEYWORDS", ""))
        if not matcher.tokens:
            return [], []
        lines: List[str] = []
        ids: List[str] = []
        now_time = fmt_time()
        for row in self._load_rss_log_data().get("hit_logs", []):
            id_ = str(row.get("id", ""))
            if not id_ or id_ in exclude_ids:
                continue
            title = str(row.get("title", ""))
            hit = matcher.match(title)
            if not hit:
                continue
            state_entry = self.state.entries.get(id_)
            already_sent = bool(state_entry.get("sent")) if state_entry else bool(row.get("sent"))
            if already_sent:
                continue
            status = str(row.get("push_status", "未推送"))
            if status == "已推送":
                continue
            lines.extend([
                f"🎯node:【{hit}】",
                f"📆时间: {now_time}",
                f"🔖标题: {title}",
                f"🧬链接: {row.get('url', '')}",
                "",
            ])
            ids.append(id_)
        return lines, ids

    def refresh_once(self) -> Tuple[str, int]:
        self.reload_config()
        ok, msg = validate_config(self.config)
        if not ok:
            self.logger.error(f"[node] {msg}")
            return "error", 0

        status, body = self.fetch_rss()
        if status == "not_modified":
            self.state.export_last_node_txt()
            return status, 0
        if status != "ok" or body is None:
            return "error", 0

        parse_status, posts = self.parse_posts(body)
        if parse_status == "blocked":
            self.logger.error("[node] 可能被挑战页拦截")
            return "blocked", 0
        if parse_status == "empty":
            self.logger.error("[node] 未提取到帖子")
            return "empty", 0
        if parse_status != "ok":
            return "error", 0

        changes = self.state.merge_posts(posts)
        self.state.save()
        self.append_rss_logs(posts)
        if changes > 0:
            self.logger.info(f"[node] 缓存更新 {changes} 条")
        return "ok", changes

    def _collect_matches(self, window: int, mark_sent: bool) -> Tuple[str, List[str]]:
        self.reload_config()
        matcher = KeywordMatcher(self.config.get("KEYWORDS", ""))
        if not matcher.tokens:
            return "", []
        now_time = fmt_time()
        lines: List[str] = []
        ids_to_mark: List[str] = []
        for entry in self.state.latest_entries(window):
            if mark_sent and entry.get("sent"):
                continue
            title = str(entry.get("title", ""))
            hit = matcher.match(title)
            if not hit:
                continue
            lines.extend([
                f"🎯node:【{hit}】",
                f"📆时间: {now_time}",
                f"🔖标题: {title}",
                f"🧬链接: {entry.get('url', '')}",
                "",
            ])
            ids_to_mark.append(str(entry.get("id", "")))
        return "\n".join(lines).rstrip(), ids_to_mark

    def auto_push_once(self) -> int:
        text, ids_to_mark = self._collect_matches(MATCH_WINDOW, mark_sent=True)
        extra_lines, extra_ids = self._pending_hit_log_matches(exclude_ids=set(ids_to_mark))
        if extra_lines:
            text = (text + "\n\n" if text else "") + "\n".join(extra_lines).rstrip()
            ids_to_mark.extend(extra_ids)
        if not text or not ids_to_mark:
            return 0
        if not self.send_message(text):
            self._update_rss_push_status(ids_to_mark, "推送失败")
            return -1
        changed = False
        for id_ in ids_to_mark:
            entry = self.state.entries.get(id_)
            if entry and not entry.get("sent"):
                entry["sent"] = True
                changed = True
        if changed:
            self.state.save()
        self._update_rss_push_status(ids_to_mark, "已推送")
        self.logger.event(f"[node] 自动推送成功 {len(ids_to_mark)} 条")
        return len(ids_to_mark)

    def manual_push(self) -> int:
        text, ids_to_mark = self._collect_matches(MANUAL_PUSH_WINDOW, mark_sent=False)
        if not text or not ids_to_mark:
            return 0
        return len(ids_to_mark) if self.send_message(text) else -1

    def print_latest(self, limit: int = 10) -> None:
        latest = self.state.latest_entries(limit)
        if not latest:
            print("暂无缓存，请先执行「手动刷新」")
            return
        print("最新10条（最新在下）：")
        for idx, entry in enumerate(latest, 1):
            tag = "已推送" if entry.get("sent") else "未推送"
            print(f"{idx}) [{entry['id']}] ({tag}) {entry['title']}")
            print(f"    {entry['url']}")

    def test_notification(self) -> bool:
        msg = "\n".join([
            "🎯node",
            f"📆时间: {fmt_time()}",
            "🔖标题: 这是来自 Python 脚本的测试推送",
            f"🧬链接: {self.config.get('NS_URL', DEFAULT_URL)}",
        ])
        return self.send_message(msg)

    def trim_logs_if_needed(self, every_n_loops: int, loop_count: int) -> None:
        if every_n_loops <= 0 or loop_count % every_n_loops != 0:
            return
        today = datetime.now().strftime("%Y-%m-%d")
        last_day = ""
        if LOG_RESET_FILE.exists():
            try:
                last_day = LOG_RESET_FILE.read_text(encoding="utf-8").strip()
            except Exception:
                last_day = ""
        if last_day != today:
            for path in (LOG_FILE, CRON_LOG):
                path.write_text("", encoding="utf-8")
            LOG_RESET_FILE.write_text(today, encoding="utf-8")
        for path, max_lines in ((LOG_FILE, 60), (CRON_LOG, 60), (LAST_NODE_TXT, 30)):
            if not path.exists():
                continue
            try:
                with path.open("r", encoding="utf-8") as fh:
                    lines = fh.readlines()
                if len(lines) > max_lines:
                    with path.open("w", encoding="utf-8") as fh:
                        fh.writelines(lines[-max_lines:])
            except Exception:
                continue

    def monitor_loop(self) -> int:
        self.reload_config()
        ok, msg = validate_config(self.config)
        if not ok:
            print(f"❌ {msg}")
            self.logger.error(f"[node] {msg}")
            return 1

        interval = max(15, safe_int(self.config.get("INTERVAL_SEC", "15"), 15))
        self.logger.event(f"[node] Python 监控已启动，每 {interval} 秒轮询")
        loop_count = 0
        last_paused_log = 0.0
        while True:
            loop_count += 1
            started = time.monotonic()
            self.reload_config()
            interval = max(15, safe_int(self.config.get("INTERVAL_SEC", "15"), 15))

            if not is_run_enabled():
                if self.logger.debug and started - last_paused_log >= 60:
                    self.logger.info("[node] 网页运行开关已关闭，本轮跳过刷新和推送")
                    last_paused_log = started
                self.trim_logs_if_needed(40, loop_count)
                time.sleep(interval)
                continue

            status, changed = self.refresh_once()
            if self.logger.debug:
                self.logger.info(f"[node] 本轮刷新状态={status} 变化={changed}")
            push_count = self.auto_push_once()
            if self.logger.debug:
                self.logger.info(f"[node] 本轮推送结果={push_count}")
            self.trim_logs_if_needed(40, loop_count)
            elapsed = time.monotonic() - started
            sleep_time = max(1.0, interval - elapsed)
            time.sleep(sleep_time)


def acquire_lock(lock_path: Path, pid_path: Path) -> Optional[object]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = lock_path.open("w")
    try:
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            fd.close()
            return None
        fd.close()
        raise
    fd.write(str(os.getpid()))
    fd.flush()
    pid_path.write_text(str(os.getpid()), encoding="utf-8")
    return fd


def remove_pid_file(path: Path = PID_FILE) -> None:
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


def read_pid(path: Path = PID_FILE) -> int:
    if not path.exists():
        return 0
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except Exception:
        return 0


def is_target_process(pid: int, markers: List[str]) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_text(encoding="utf-8", errors="ignore").replace("\x00", " ")
        return all(marker in cmdline for marker in markers)
    except Exception:
        return False


def build_keyword_handler(cfg: Dict[str, str]):
    settings = keyword_web_settings(cfg)
    save_pin = settings["pin"]

    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, payload: Dict[str, object], status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_form(self) -> Dict[str, List[str]]:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8", errors="ignore")
            return parse_qs(body, keep_blank_values=True)

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/api/runtime-status":
                self._send_json({"ok": True, "enabled": is_run_enabled(), "server_time": now_str()})
                return
            if parsed.path == "/api/rss-logs":
                query = parse_qs(parsed.query, keep_blank_values=True)
                mode = (query.get("mode", ["all"])[0] or "all").strip().lower()
                monitor = NodeMonitor()
                cfg_now = load_runtime_config()
                interval = max(15, safe_int(cfg_now.get("INTERVAL_SEC", "20"), 20))
                logs = monitor.get_rss_logs(mode=mode, limit=20)
                self._send_json({
                    "ok": True,
                    "mode": "hits" if mode in {"hit", "hits", "matched"} else "all",
                    "logs": logs,
                    "server_time": now_str(),
                    "refresh_interval_sec": interval,
                    "runtime_enabled": is_run_enabled(),
                })
                return
            self.respond_page(read_keywords(), "", False)

        def do_DELETE(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/api/rss-logs":
                NodeMonitor().clear_rss_logs()
                self._send_json({"ok": True, "message": "RSS日志已清除", "server_time": now_str()})
                return
            self._send_json({"ok": False, "message": "Not found"}, status=404)

        def do_POST(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/api/runtime-toggle":
                form = self._read_form()
                raw = (form.get("enabled", [""])[0] or "").strip().lower()
                enabled = raw in {"1", "true", "on", "yes", "run", "running"}
                set_run_enabled(enabled)
                self._send_json({"ok": True, "enabled": enabled, "server_time": now_str()})
                return
            if parsed.path == "/api/restart-web":
                WEB_RESTART_FILE.write_text(now_str(), encoding="utf-8")
                self._send_json({"ok": True, "message": "网页服务正在重启", "server_time": now_str()})
                return
            if parsed.path == "/api/rss-refresh":
                if not is_run_enabled():
                    self._send_json({
                        "ok": False,
                        "status": "disabled",
                        "changed": 0,
                        "pushed": 0,
                        "server_time": now_str(),
                    })
                    return
                monitor = NodeMonitor()
                status, changed = monitor.refresh_once()
                pushed = monitor.auto_push_once() if status in {"ok", "not_modified"} else 0
                self._send_json({
                    "ok": status in {"ok", "not_modified"},
                    "status": status,
                    "changed": changed,
                    "pushed": pushed,
                    "server_time": now_str(),
                })
                return
            if parsed.path == "/api/rss-logs/clear":
                NodeMonitor().clear_rss_logs()
                self._send_json({"ok": True, "message": "RSS日志已清除", "server_time": now_str()})
                return

            form = self._read_form()
            new_keywords = form.get("keywords", [""])[0].strip()
            try:
                update_keywords(new_keywords)
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
            except Exception as exc:
                self.respond_page(new_keywords, f"保存失败: {exc}", True, status=500)

        def log_message(self, fmt, *args):
            return

        def respond_page(self, keywords: str, message: str, editing: bool, status: int = 200):
            safe_keywords = html.escape(keywords, quote=True)
            safe_message = html.escape(message, quote=True)
            readonly_attr = "" if editing else "readonly"
            action_label = "保存" if editing else "修改"
            msg_class = "msg ok" if message == "保存成功" else "msg err"
            if not message:
                msg_class = "msg"
            html_doc = '''<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>node捕🐟</title>
  <style>
    :root {
      --bg: #07111d;
      --bg2: #050b14;
      --card: rgba(12, 29, 47, 0.78);
      --card-strong: rgba(15, 38, 58, 0.86);
      --panel: rgba(7, 17, 29, 0.62);
      --panel-readonly: rgba(10, 23, 38, 0.56);
      --text: #edf7ff;
      --muted: rgba(224, 241, 252, 0.58);
      --line: rgba(126, 232, 216, 0.18);
      --line2: rgba(132, 180, 210, 0.22);
      --primary: #25ddbf;
      --primary2: #13ae97;
      --green: #63c83d;
      --yellow: #f6c343;
      --danger: #ef4444;
      --shadow: 0 28px 70px rgba(0, 10, 22, 0.46);
      --radius: 30px;
      --control-radius: 18px;
    }
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
    html, body { margin: 0; padding: 0; min-height: 100%; }
    body {
      min-height: 100vh;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 74% 12%, rgba(24, 210, 176, 0.18), transparent 30%),
        radial-gradient(circle at 18% 20%, rgba(78, 126, 180, 0.18), transparent 34%),
        linear-gradient(180deg, #0d2133 0%, var(--bg) 58%, var(--bg2) 100%);
      padding: 20px 14px;
      overflow-x: hidden;
    }
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(126,232,216,0.045) 1px, transparent 1px),
        linear-gradient(90deg, rgba(126,232,216,0.045) 1px, transparent 1px);
      background-size: 46px 46px;
      opacity: 0.24;
      mask-image: linear-gradient(180deg, rgba(0,0,0,0.9), transparent 82%);
    }
    .wrap { position: relative; z-index: 1; width: 100%; max-width: 980px; margin: 0 auto; }
    .hero {
      border-radius: var(--radius);
      padding: 24px 24px 22px;
      margin-bottom: 16px;
      background:
        linear-gradient(135deg, rgba(126,232,216,0.14), transparent 25%),
        linear-gradient(180deg, rgba(22,47,68,0.82), rgba(9,21,35,0.78));
      border: 1px solid var(--line2);
      box-shadow: var(--shadow), inset 0 1px 0 rgba(255,255,255,0.10);
      backdrop-filter: blur(20px) saturate(145%);
      -webkit-backdrop-filter: blur(20px) saturate(145%);
      overflow: hidden;
    }
    .hero-line { display: flex; align-items: center; justify-content: space-between; gap: 14px; }
    h1 {
      margin: 0;
      font-size: clamp(34px, 7vw, 48px);
      line-height: 1.08;
      letter-spacing: 1.8px;
      font-weight: 900;
      background: linear-gradient(180deg, #ffffff 0%, #c9f7ef 54%, #7bb7d0 100%);
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
      text-shadow: 0 16px 36px rgba(0,10,25,0.42);
      white-space: nowrap;
    }
    .hero-sub { margin-top: 8px; color: var(--muted); font-size: 13px; line-height: 1.55; }
    .card {
      width: 100%;
      margin: 0 auto 16px;
      padding: 18px;
      border-radius: 24px;
      background: linear-gradient(180deg, var(--card) 0%, rgba(8, 20, 34, 0.72) 100%);
      border: 1px solid var(--line2);
      box-shadow: 0 18px 48px rgba(0, 10, 22, 0.30), inset 0 1px 0 rgba(255,255,255,0.08);
      backdrop-filter: blur(18px) saturate(135%);
      -webkit-backdrop-filter: blur(18px) saturate(135%);
    }
    .keyword-card { padding: 16px; }
    .compact-row { display: grid; grid-template-columns: 1fr auto; gap: 10px; align-items: stretch; }
    textarea {
      width: 100%; min-height: 96px; resize: vertical;
      border: 1px solid var(--line); border-radius: var(--control-radius);
      background: linear-gradient(180deg, rgba(126,232,216,0.08), rgba(255,255,255,0.025)), var(--panel);
      color: var(--text); font-size: 16px; line-height: 1.55;
      padding: 13px 14px; outline: none; appearance: none;
      transition: border-color .2s ease, box-shadow .2s ease, transform .2s ease, background .2s ease;
    }
    textarea::placeholder { color: rgba(224, 241, 252, 0.42); }
    textarea[readonly] { background: var(--panel-readonly); color: rgba(237,247,255,.82); caret-color: transparent; cursor: default; pointer-events: none; user-select: none; }
    textarea:focus { border-color: rgba(24,210,176,0.68); box-shadow: 0 0 0 4px rgba(24,210,176,0.10), 0 0 28px rgba(24,210,176,0.12); transform: translateY(-1px); }
    .side-actions { display: flex; flex-direction: column; gap: 8px; min-width: 86px; }
    button {
      border: 1px solid rgba(126,232,216,0.28); border-radius: 999px;
      min-height: 38px; min-width: 78px; padding: 0 16px;
      font-size: 14px; font-weight: 850; letter-spacing: 1px; cursor: pointer;
      background: linear-gradient(180deg, rgba(37,221,191,.95) 0%, rgba(19,174,151,.92) 58%, rgba(11,120,107,.92) 100%);
      color: #ecfffb;
      box-shadow: 0 14px 30px rgba(0,20,35,0.28), inset 0 1px 0 rgba(255,255,255,0.24);
      transition: transform .16s ease, filter .16s ease, box-shadow .16s ease, background .16s ease;
    }
    button:hover { transform: translateY(-1px); filter: brightness(1.06); }
    button:active { transform: translateY(1px); }
    button.secondary { background: rgba(255,255,255,.10); border-color: rgba(255,255,255,.24); color: #e8f7ff; box-shadow: none; }
    button.active { background: #63c83d; border-color: #63c83d; color: #fff; box-shadow: none; }
    button.danger { background: rgba(255,255,255,.08); border-color: rgba(239,68,68,.38); color: #ff8d8d; box-shadow: none; }
    .msg { min-height: 20px; text-align: center; font-size: 14px; font-weight: 800; padding-top: 8px; }
    .msg.ok { color: #7fe8d8; }
    .msg.err { color: #ff9aa2; }
    .hint-line { margin-top: 9px; display: flex; align-items: center; justify-content: center; gap: 8px; color: var(--muted); font-size: 12px; }
    .title-rule { margin-top: 8px; color: rgba(224,241,252,.68); font-size: 13px; line-height: 1.55; }
    .log-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
    h2 { margin: 0; font-size: 22px; letter-spacing: .6px; color: #effcff; }
    .log-meta { color: var(--muted); font-size: 13px; }
    .log-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin: 10px 0 12px; }
    .log-card { display: none; }
    .log-card.show { display: block; }
    .switch-group { display: inline-flex; align-items: center; justify-content: flex-end; gap: 14px; flex-wrap: wrap; }
    .switch-wrap { display: inline-flex; align-items: center; gap: 9px; color: #dcefff; font-weight: 800; }
    .switch-label { color: var(--yellow); transition: color .2s ease, text-shadow .2s ease; }
    .switch-wrap.on .switch-label { color: var(--green); text-shadow: 0 0 18px rgba(99,200,61,.28); }
    .switch { position: relative; width: 48px; height: 27px; display: inline-block; }
    .switch input { opacity: 0; width: 0; height: 0; }
    .slider { position: absolute; cursor: pointer; inset: 0; background: rgba(255,255,255,.12); border: 1px solid rgba(255,255,255,.18); border-radius: 999px; transition: .2s; }
    .slider::before { content: ""; position: absolute; width: 21px; height: 21px; left: 3px; top: 2px; border-radius: 50%; background: #d9eafe; transition: .2s; box-shadow: 0 2px 8px rgba(0,0,0,.25); }
    .switch input:checked + .slider { background: rgba(37,221,191,.42); border-color: rgba(126,232,216,.45); }
    .switch input:checked + .slider::before { transform: translateX(21px); background: #7fe8d8; }
    .table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 18px; background: rgba(7,17,29,0.38); }
    table { width: 100%; border-collapse: collapse; min-width: 760px; }
    th, td { padding: 10px 12px; border-bottom: 1px solid rgba(126,232,216,.12); text-align: left; vertical-align: top; font-size: 14px; line-height: 1.45; }
    th { color: #dff8f4; background: rgba(126,232,216,.08); font-size: 13px; letter-spacing: .5px; }
    tr:last-child td { border-bottom: none; }
    .time { color: rgba(224,241,252,.68); white-space: nowrap; }
    .title { font-weight: 750; color: #edf7ff; word-break: break-all; }
    .url a { color: #7fe8d8; text-decoration: none; font-weight: 800; }
    .url a:hover { text-decoration: underline; }
    .tag { display: inline-flex; align-items: center; border-radius: 999px; padding: 3px 9px; font-size: 12px; font-weight: 900; white-space: nowrap; }
    .tag.hit { color: #ecfffb; background: rgba(99,200,61,.78); }
    .tag.miss { color: #c8d7ea; background: rgba(255,255,255,.10); }
    .tag.pending { color: #ffe7b8; background: rgba(217,119,6,.24); border: 1px solid rgba(217,119,6,.35); }
    .tag.fail { color: #ffd2d2; background: rgba(239,68,68,.20); border: 1px solid rgba(239,68,68,.38); }
    .empty { text-align: center; color: var(--muted); padding: 28px 12px; }
    @media (max-width: 640px) {
      body { padding: 14px 10px; }
      .hero { padding: 22px 18px; border-radius: 24px; }
      .hero-line { align-items: flex-start; }
      .switch-group { flex-direction: column; align-items: flex-end; gap: 10px; }
      h1 { font-size: 34px; }
      .card { padding: 14px; border-radius: 22px; }
      .compact-row { grid-template-columns: 1fr; }
      textarea { min-height: 88px; font-size: 15px; }
      .side-actions { flex-direction: row; min-width: 0; }
      .side-actions button { flex: 1; }
      .log-actions { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; }
      .log-actions button { min-width: 0; padding: 0 6px; font-size: 12px; }
      .log-head { align-items: flex-start; }
    }
    /* 自定义确认弹窗 */
    .modal-overlay {
      position: fixed; inset: 0; z-index: 9999;
      display: flex; align-items: center; justify-content: center;
      background: rgba(0,0,0,0.55);
      backdrop-filter: blur(4px);
      -webkit-backdrop-filter: blur(4px);
      animation: modalFadeIn .18s ease;
    }
    .modal-overlay.hidden { display: none; }
    @keyframes modalFadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    @keyframes modalScaleIn {
      from { opacity: 0; transform: scale(.92) translateY(8px); }
      to { opacity: 1; transform: scale(1) translateY(0); }
    }
    .modal-box {
      background: linear-gradient(180deg, #132b40 0%, #0d2133 100%);
      border: 1px solid rgba(126,232,216,0.25);
      border-radius: 24px;
      padding: 28px 32px 24px;
      max-width: 420px;
      width: 90%;
      box-shadow: 0 30px 80px rgba(0,10,22,0.6);
      animation: modalScaleIn .20s ease;
    }
    .modal-title {
      font-size: 18px; font-weight: 850; color: #edf7ff;
      margin-bottom: 12px;
    }
    .modal-body {
      font-size: 15px; line-height: 1.6; color: rgba(224,241,252,0.82);
      margin-bottom: 24px;
    }
    .modal-actions {
      display: flex; gap: 12px; justify-content: flex-end;
    }
    .modal-actions button {
      min-width: 80px; padding: 0 20px;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div class="hero-line">
        <div>
          <h1>node捕🐟</h1>
          <div class="title-rule">关键词规则：空格或逗号分隔规则，多个关键词采用 &amp; 间隔</div>
        </div>
        <div class="switch-group">
          <label id="runSwitchWrap" class="switch-wrap on" title="开启或暂停自动监控和推送">
            <span id="runLabel" class="switch-label">运行</span>
            <span class="switch"><input id="runToggle" type="checkbox" checked><span class="slider"></span></span>
          </label>
          <label id="logSwitchWrap" class="switch-wrap" title="显示或隐藏RSS日志">
            <span id="logLabel" class="switch-label">日志</span>
            <span class="switch"><input id="logToggle" type="checkbox"><span class="slider"></span></span>
          </label>
        </div>
      </div>
    </section>

    <section class="card keyword-card">
      <form id="keywordForm" method="post" autocomplete="off">
        <div class="compact-row">
          <textarea id="keywords" name="keywords" spellcheck="false" __READONLY__ placeholder="例如：抽奖 甲&乙 amd&7950x&盒装&国行">__SAFE_KEYWORDS__</textarea>
          <div class="side-actions">
            <button id="actionBtn" type="button" onclick="handleAction()">__ACTION_LABEL__</button>
          </div>
        </div>
        <div class="__MSG_CLASS__">__SAFE_MESSAGE__</div>
      </form>
    </section>

    <section id="logCard" class="card log-card">
      <div class="log-head">
        <h2>RSS日志 <span class="log-meta">最新20条</span></h2>
        <div class="log-meta" id="logMeta">等待刷新</div>
      </div>
      <div class="log-actions">
        <button type="button" class="secondary" onclick="fetchLogs(true)">刷新</button>
        <button id="btnAll" type="button" class="active" onclick="setMode('all')">RSS全部</button>
        <button id="btnHits" type="button" class="secondary" onclick="setMode('hits')">命中</button>
        <button type="button" class="danger" onclick="clearLogs()">清除</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th style="width:132px;">时间</th>
              <th style="width:82px;">结果</th>
              <th style="width:102px;">推送</th>
              <th style="width:112px;">命中词</th>
              <th>标题</th>
              <th style="width:62px;">链接</th>
            </tr>
          </thead>
          <tbody id="rssLogBody"><tr><td class="empty" colspan="6">日志已隐藏</td></tr></tbody>
        </table>
      </div>
    </section>
  </div>
  <script>
    let logMode = localStorage.getItem('nodeRssLogMode') || 'all';
    let logTimer = null;
    let runStatusTimer = null;

    let pendingConfirmCallback = null;

    function handleAction() {
      const form = document.getElementById('keywordForm');
      const textarea = document.getElementById('keywords');
      const actionBtn = document.getElementById('actionBtn');

      if (textarea.hasAttribute('readonly')) {
        textarea.removeAttribute('readonly');
        actionBtn.textContent = '保存';
        setTimeout(() => {
          textarea.focus();
          textarea.setSelectionRange(textarea.value.length, textarea.value.length);
        }, 50);
        return;
      }
      document.getElementById('confirmMessage').textContent = '确认修改关键词并保存吗？';
      pendingConfirmCallback = () => form.submit();
      document.getElementById('confirmModal').classList.remove('hidden');
    }

    function submitKeywords() {
      const cb = pendingConfirmCallback;
      pendingConfirmCallback = null;
      document.getElementById('confirmModal').classList.add('hidden');
      if (cb) cb();
    }

    function closeConfirmModal() {
      pendingConfirmCallback = null;
      document.getElementById('confirmModal').classList.add('hidden');
    }
    function escapeHtml(text) {
      return String(text || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function compactTime(value) {
      if (!value) return '';
      return String(value).replace(/^\\d{4}-/, '').replace(' ', '<br>');
    }

    function setSwitchLabelState(wrapId, enabled) {
      const wrap = document.getElementById(wrapId);
      if (wrap) wrap.classList.toggle('on', Boolean(enabled));
    }

    function setRunVisible(enabled) {
      const toggle = document.getElementById('runToggle');
      toggle.checked = Boolean(enabled);
      setSwitchLabelState('runSwitchWrap', enabled);
    }

    async function fetchRunStatus() {
      try {
        const res = await fetch('/api/runtime-status', { cache: 'no-store' });
        const data = await res.json();
        if (data && data.ok) setRunVisible(Boolean(data.enabled));
      } catch (err) {}
    }

    async function setRunEnabled(enabled) {
      setRunVisible(enabled);
      try {
        const body = new URLSearchParams();
        body.set('enabled', enabled ? '1' : '0');
        const res = await fetch('/api/runtime-toggle', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
          body: body.toString(),
          cache: 'no-store'
        });
        const data = await res.json();
        if (data && data.ok) setRunVisible(Boolean(data.enabled));
        if (isLogVisible()) fetchLogs(false);
      } catch (err) {
        await fetchRunStatus();
        alert('运行状态设置失败');
      }
    }

    function isLogVisible() {
      return document.getElementById('logToggle').checked;
    }

    function setLogVisible(visible, shouldFetch) {
      const toggle = document.getElementById('logToggle');
      const card = document.getElementById('logCard');
      toggle.checked = Boolean(visible);
      setSwitchLabelState('logSwitchWrap', visible);
      card.classList.toggle('show', Boolean(visible));
      localStorage.setItem('nodeRssLogVisible', visible ? 'true' : 'false');
      if (visible) {
        if (shouldFetch) fetchLogs(false);
      } else if (logTimer) {
        clearInterval(logTimer);
        logTimer = null;
      }
    }

    function setMode(mode) {
      logMode = mode === 'hits' ? 'hits' : 'all';
      localStorage.setItem('nodeRssLogMode', logMode);
      document.getElementById('btnAll').classList.toggle('active', logMode === 'all');
      document.getElementById('btnAll').classList.toggle('secondary', logMode !== 'all');
      document.getElementById('btnHits').classList.toggle('active', logMode === 'hits');
      document.getElementById('btnHits').classList.toggle('secondary', logMode !== 'hits');
      if (isLogVisible()) fetchLogs(false);
    }

    function renderLogs(logs) {
      const body = document.getElementById('rssLogBody');
      if (!logs || logs.length === 0) {
        body.innerHTML = '<tr><td class="empty" colspan="6">暂无RSS日志</td></tr>';
        return;
      }
      body.innerHTML = logs.map(row => {
        const matched = Boolean(row.matched);
        const tag = matched ? '<span class="tag hit">命中</span>' : '<span class="tag miss">未命中</span>';
        const statusText = matched ? (row.push_status || (row.sent ? '已推送' : '未推送')) : '-';
        const statusClass = statusText === '已推送' ? 'hit' : (statusText === '推送失败' ? 'fail' : 'pending');
        const statusTag = matched ? `<span class="tag ${statusClass}">${escapeHtml(statusText)}</span>` : '-';
        const hit = row.hit ? escapeHtml(row.hit) : '-';
        const title = escapeHtml(row.title || '');
        const url = escapeHtml(row.url || '');
        const link = url ? `<a href="${url}" target="_blank" rel="noopener noreferrer">打开</a>` : '-';
        return `<tr>
          <td class="time">${compactTime(row.checked_at || row.first_seen_at || '')}</td>
          <td>${tag}</td>
          <td>${statusTag}</td>
          <td>${hit}</td>
          <td class="title">${title}</td>
          <td class="url">${link}</td>
        </tr>`;
      }).join('');
    }

    async function fetchLogs(manual) {
      if (!isLogVisible()) {
        setLogVisible(true, false);
      }
      const meta = document.getElementById('logMeta');
      if (manual) meta.textContent = '刷新中...';
      try {
        const res = await fetch(`/api/rss-logs?mode=${encodeURIComponent(logMode)}`, { cache: 'no-store' });
        const data = await res.json();
        renderLogs(data.logs || []);
        const interval = Math.max(15, Number(data.refresh_interval_sec || 20));
        meta.textContent = `上次刷新：${data.server_time || ''}；自动刷新：${interval}秒`;
        resetTimer(interval);
      } catch (err) {
        meta.textContent = '日志读取失败';
      }
    }

    function resetTimer(intervalSec) {
      if (logTimer) clearInterval(logTimer);
      if (!isLogVisible()) return;
      logTimer = setInterval(() => fetchLogs(false), Math.max(15, intervalSec) * 1000);
    }

    async function clearLogs() {
      if (!confirm('确定清除RSS日志吗？不会清除已推送状态。')) return;
      try {
        await fetch('/api/rss-logs', { method: 'DELETE' });
        await fetchLogs(false);
      } catch (err) {
        alert('清除失败');
      }
    }

    document.getElementById('runToggle').addEventListener('change', (event) => {
      setRunEnabled(event.target.checked);
    });

    document.getElementById('logToggle').addEventListener('change', (event) => {
      setLogVisible(event.target.checked, true);
    });

    setMode(logMode);

    document.getElementById('confirmModal').addEventListener('click', (e) => {
      if (e.target === e.currentTarget) closeConfirmModal();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeConfirmModal();
    });
  </script>
  <!-- 自定义确认弹窗 -->
  <div id="confirmModal" class="modal-overlay hidden">
    <div class="modal-box">
      <div class="modal-title">确认操作</div>
      <div class="modal-body" id="confirmMessage">确认修改关键词并保存吗？</div>
      <div class="modal-actions">
        <button class="secondary" onclick="closeConfirmModal()">取消</button>
        <button onclick="submitKeywords()">确认</button>
      </div>
    </div>
  </div>
</body>
</html>'''
            html_doc = (html_doc
                .replace("__SAFE_KEYWORDS__", safe_keywords)
                .replace("__SAFE_MESSAGE__", safe_message)
                .replace("__READONLY__", readonly_attr)
                .replace("__ACTION_LABEL__", action_label)
                .replace("__MSG_CLASS__", msg_class))
            payload = html_doc.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)


    return Handler

def build_keyword_web_server(cfg: Dict[str, str]) -> ThreadingHTTPServer:
    settings = keyword_web_settings(cfg)
    server = ThreadingHTTPServer((settings["host"], int(settings["port"])), build_keyword_handler(cfg))
    if settings["ssl_cert"] and settings["ssl_key"]:
        cert_path = Path(settings["ssl_cert"])
        key_path = Path(settings["ssl_key"])
        if not cert_path.is_file() or not key_path.is_file():
            raise FileNotFoundError("证书文件不存在或不是文件")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def cmd_run() -> int:
    lock_handle = acquire_lock(LOCK_FILE, PID_FILE)
    if lock_handle is None:
        print("node Python 监控已在运行，跳过重复启动")
        return 0

    def _cleanup(*_args):
        remove_pid_file(PID_FILE)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)
    try:
        monitor = NodeMonitor()
        return monitor.monitor_loop()
    finally:
        remove_pid_file(PID_FILE)
        try:
            lock_handle.close()
        except Exception:
            pass


def cmd_refresh() -> int:
    monitor = NodeMonitor()
    status, changed = monitor.refresh_once()
    if status == "not_modified":
        print("ℹ️ RSS 未更新（304）")
        return 0
    if status == "ok":
        print(f"✅ 刷新完成，更新 {changed} 条")
        return 0
    if status == "blocked":
        print("⚠️ 可能被挑战页拦截")
        return 1
    print("❌ 刷新失败")
    return 1


def cmd_auto_push() -> int:
    monitor = NodeMonitor()
    count = monitor.auto_push_once()
    if count > 0:
        print(f"✅ 自动推送完成 {count} 条")
        return 0
    if count == 0:
        print("⚠️ 无匹配或均已推送")
        return 0
    print("❌ 自动推送失败")
    return 1


def cmd_manual_push() -> int:
    monitor = NodeMonitor()
    count = monitor.manual_push()
    if count > 0:
        print(f"✅ 推送完成（匹配 {count} 条）")
        return 0
    if count == 0:
        print("⚠️ 无匹配关键词帖子")
        return 0
    print("❌ 推送失败")
    return 1


def cmd_print_latest() -> int:
    monitor = NodeMonitor()
    monitor.print_latest()
    return 0


def cmd_test() -> int:
    monitor = NodeMonitor()
    if monitor.test_notification():
        print("✅ 测试推送已发送")
        return 0
    print("❌ 测试推送发送失败")
    return 1


def cmd_status() -> int:
    pid = read_pid(PID_FILE)
    if pid and (is_target_process(pid, ["node.py", "run"]) or is_target_process(pid, ["node.py", "run-all"])):
        print(f"RUNNING pid={pid}")
        return 0
    remove_pid_file(PID_FILE)
    print("STOPPED")
    return 1


def cmd_show_keywords() -> int:
    print(read_keywords())
    return 0


def cmd_update_keywords(argv: List[str]) -> int:
    if len(argv) < 3:
        print("usage: node.py update-keywords <keywords>")
        return 1
    update_keywords(" ".join(argv[2:]).strip())
    print("✅ 关键词已更新")
    return 0


def cmd_keyword_web_status() -> int:
    cfg = load_runtime_config()
    settings = keyword_web_settings(cfg)
    pid = read_pid(WEB_PID_FILE)
    if pid and (is_target_process(pid, ["node.py", "keyword-web"]) or is_target_process(pid, ["node.py", "run-all"])):
        print(f"RUNNING pid={pid} url={settings['url']}")
        return 0
    remove_pid_file(WEB_PID_FILE)
    print(f"STOPPED url={settings['url']}")
    return 1


def cmd_keyword_web() -> int:
    cfg = load_runtime_config()
    settings = keyword_web_settings(cfg)
    lock_handle = acquire_lock(WEB_LOCK_FILE, WEB_PID_FILE)
    if lock_handle is None:
        print(f"node keyword web already running on {settings['url']}")
        return 0

    def _cleanup(*_args):
        remove_pid_file(WEB_PID_FILE)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)
    try:
        server = build_keyword_web_server(cfg)
        print(f"node keyword web running on {settings['url']}", flush=True)
        server.serve_forever()
        return 0
    finally:
        remove_pid_file(WEB_PID_FILE)
        try:
            lock_handle.close()
        except Exception:
            pass


def cmd_run_all() -> int:
    """Run monitor loop and keyword web in one process for systemd deployment."""
    cfg = load_runtime_config()
    ok, msg = validate_config(cfg)
    if not ok:
        print(f"❌ {msg}")
        Logger(False).error(f"[node] {msg}")
        return 1

    monitor_lock = acquire_lock(LOCK_FILE, PID_FILE)
    if monitor_lock is None:
        print("node Python 监控已在运行，跳过重复启动")
        return 0

    web_lock = acquire_lock(WEB_LOCK_FILE, WEB_PID_FILE)
    if web_lock is None:
        remove_pid_file(PID_FILE)
        try:
            monitor_lock.close()
        except Exception:
            pass
        print("node keyword web already running，跳过重复启动")
        return 0

    def _cleanup(*_args):
        remove_pid_file(PID_FILE)
        remove_pid_file(WEB_PID_FILE)
        os._exit(0)

    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)

    try:
        monitor = NodeMonitor()
        thread = threading.Thread(target=monitor.monitor_loop, name="node-monitor", daemon=True)
        thread.start()

        while True:
            cfg = load_runtime_config()
            server = build_keyword_web_server(cfg)
            settings = keyword_web_settings(cfg)
            print(f"node run-all started; monitor interval={max(15, safe_int(cfg.get('INTERVAL_SEC', '15'), 15))}s; keyword web={settings['url']}", flush=True)

            def watch_restart(svr):
                while True:
                    time.sleep(1)
                    if WEB_RESTART_FILE.exists():
                        try:
                            WEB_RESTART_FILE.unlink()
                        except Exception:
                            pass
                        svr.shutdown()
                        break

            threading.Thread(target=watch_restart, args=(server,), daemon=True).start()
            server.serve_forever()
            server.server_close()
        return 0
    finally:
        remove_pid_file(PID_FILE)
        remove_pid_file(WEB_PID_FILE)
        try:
            monitor_lock.close()
        except Exception:
            pass
        try:
            web_lock.close()
        except Exception:
            pass


def main(argv: List[str]) -> int:
    ensure_workdir()
    if len(argv) < 2:
        print("usage: node.py [run|run-all|refresh|auto-push|manual-push|print-latest|test|status|keyword-web|keyword-web-status|show-keywords|update-keywords]")
        return 1
    cmd = argv[1]
    if cmd == "run":
        return cmd_run()
    if cmd == "run-all":
        return cmd_run_all()
    if cmd == "refresh":
        return cmd_refresh()
    if cmd == "auto-push":
        return cmd_auto_push()
    if cmd == "manual-push":
        return cmd_manual_push()
    if cmd == "print-latest":
        return cmd_print_latest()
    if cmd == "test":
        return cmd_test()
    if cmd == "status":
        return cmd_status()
    if cmd == "keyword-web":
        return cmd_keyword_web()
    if cmd == "keyword-web-status":
        return cmd_keyword_web_status()
    if cmd == "show-keywords":
        return cmd_show_keywords()
    if cmd == "update-keywords":
        return cmd_update_keywords(argv)
    print(f"unknown command: {cmd}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
