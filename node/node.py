#!/usr/bin/env python3
import errno
import fcntl
import hashlib
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
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs

try:
    from zoneinfo import ZoneInfo
except ImportError:  # Python < 3.9 fallback
    ZoneInfo = None

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
KEYWORDS_FILE = WORK_DIR / "keywords.json"
KEYWORDS_BACKUP_FILE = WORK_DIR / "keywords.json.bak"
KEYWORDS_AUDIT_LOG = WORK_DIR / "keywords_audit.log"
SKIN_FILE = Path(os.environ.get("NODE_SKIN_FILE", str(WORK_DIR / "node_skin.css")))

_RSS_LOG_WRITE_LOCK = threading.Lock()
_STATE_WRITE_LOCK = threading.Lock()
_KEYWORDS_WRITE_LOCK = threading.Lock()

DEFAULT_URL = "https://rss.nodeseek.com/?sortBy=postTime"
DEFAULT_WEB_HOST = os.environ.get("NODE_WEB_HOST", "0.0.0.0")
DEFAULT_WEB_PORT = int(os.environ.get("NODE_WEB_PORT", "8068"))
DEFAULT_WEB_PIN = "0819"
MAX_REQUEST_SIZE = 1024 * 1024
REQUEST_TIMEOUT = 30
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

try:
    SHANGHAI_TZ = ZoneInfo("Asia/Shanghai") if ZoneInfo is not None else timezone(timedelta(hours=8), name="Asia/Shanghai")
except Exception:
    # 极简系统若缺少 tzdata，上海当前长期固定为 UTC+8，可安全回退。
    SHANGHAI_TZ = timezone(timedelta(hours=8), name="Asia/Shanghai")


def shanghai_now() -> datetime:
    """始终返回上海时间，不受 VPS 本机时区影响。"""
    return datetime.now(SHANGHAI_TZ)


def is_shanghai_quiet_hours() -> bool:
    """上海时间 00:00 <= time < 08:00 时强制静默。"""
    return 0 <= shanghai_now().hour < 8


def ensure_workdir() -> None:
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    for p in (LOG_FILE, CRON_LOG):
        if not p.exists():
            p.touch()


def now_str() -> str:
    return shanghai_now().strftime("%Y-%m-%d %H:%M:%S")


def fmt_time() -> str:
    return shanghai_now().strftime("%Y.%m.%d.%H:%M")


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
    kw = read_keywords()
    cfg["KEYWORDS"] = kw if kw else ""
    cfg.setdefault("DEBUG_LOG", "0")
    cfg.setdefault("WEB_HOST", DEFAULT_WEB_HOST)
    cfg.setdefault("WEB_PORT", str(DEFAULT_WEB_PORT))
    cfg.setdefault("WEB_PIN", DEFAULT_WEB_PIN)
    cfg.setdefault("WEB_DOMAIN", "")
    cfg.setdefault("NTFY_URL", "http://127.0.0.1:8083")
    cfg.setdefault("NTFY_USERNAME", "")
    cfg.setdefault("NTFY_PASSWORD", "")
    cfg.setdefault("NTFY_TOPIC", "node")
    cfg.setdefault("NTFY_PRIORITY", "3")
    skw = read_silent_keywords()
    cfg["SILENT_KEYWORDS"] = skw if skw else ""
    return cfg


def validate_config(cfg: Dict[str, str]) -> Tuple[bool, str]:
    required = ["NS_URL", "NTFY_URL", "NTFY_TOPIC"]
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


def _read_keywords_file(path: Path) -> Optional[Dict[str, str]]:
    if not path.exists() or path.stat().st_size <= 0:
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        return {
            "keywords": str(data.get("keywords", "")).strip(),
            "silent_keywords": str(data.get("silent_keywords", "")).strip(),
        }
    except Exception:
        return None


def _atomic_write_keywords_file(path: Path, payload: Dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _keyword_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _append_keywords_audit(source: str, client_ip: str, old_data: Dict[str, str], new_data: Dict[str, str], action: str = "save") -> None:
    try:
        line = (
            f"{now_str()} action={action} source={source or '-'} ip={client_ip or '-'} "
            f"keywords={_keyword_digest(old_data.get('keywords', ''))}->{_keyword_digest(new_data.get('keywords', ''))} "
            f"silent={_keyword_digest(old_data.get('silent_keywords', ''))}->{_keyword_digest(new_data.get('silent_keywords', ''))}\n"
        )
        with KEYWORDS_AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:
        pass


def _load_keywords_json() -> Dict[str, str]:
    data = _read_keywords_file(KEYWORDS_FILE)
    if data is not None:
        return data

    backup = _read_keywords_file(KEYWORDS_BACKUP_FILE)
    if backup is not None:
        # 主文件损坏/为空时自动恢复最近一次有效备份。
        with _KEYWORDS_WRITE_LOCK:
            current = _read_keywords_file(KEYWORDS_FILE)
            if current is None:
                _atomic_write_keywords_file(KEYWORDS_FILE, backup)
                _append_keywords_audit("recovery", "", backup, backup, action="restore")
        return backup

    return {"keywords": "", "silent_keywords": ""}


def read_keywords() -> str:
    data = _load_keywords_json()
    # keywords.json 只要是有效 JSON，就以它为准；即使关键词被用户主动清空，也不再从旧配置复活。
    if _read_keywords_file(KEYWORDS_FILE) is not None:
        return data["keywords"]

    cfg = parse_shell_config(CONFIG_FILE)
    kw = cfg.get("KEYWORDS", "").strip()
    if kw:
        _save_keywords_json(kw, data.get("silent_keywords", ""), source="config-recovery")
    return kw


def read_silent_keywords() -> str:
    return _load_keywords_json()["silent_keywords"]


def _save_keywords_json(
    keywords: str,
    silent_keywords: str,
    source: str = "internal",
    client_ip: str = "",
    allow_all_empty: bool = False,
) -> None:
    payload = {
        "keywords": str(keywords).strip(),
        "silent_keywords": str(silent_keywords).strip(),
    }
    # 最后一层保险：任何内部代码都不能无意中把两类关键词同时写空。
    # 只有 Web 端在 PIN 验证通过且用户再次确认“彻底清空”后，才显式放行。
    if not payload["keywords"] and not payload["silent_keywords"] and not allow_all_empty:
        raise ValueError("禁止未确认地清空全部关键词")
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    with _KEYWORDS_WRITE_LOCK:
        current = _read_keywords_file(KEYWORDS_FILE)
        if current is None:
            current = _read_keywords_file(KEYWORDS_BACKUP_FILE)
        old_data = current or {"keywords": "", "silent_keywords": ""}

        # 只用有效的旧数据刷新备份，避免把损坏/空文件覆盖到 .bak。
        if current is not None:
            _atomic_write_keywords_file(KEYWORDS_BACKUP_FILE, current)

        _atomic_write_keywords_file(KEYWORDS_FILE, payload)
        # 首次创建时也生成一份可恢复备份；后续保存则保留保存前的上一版。
        if current is None and _read_keywords_file(KEYWORDS_BACKUP_FILE) is None:
            _atomic_write_keywords_file(KEYWORDS_BACKUP_FILE, payload)
        _append_keywords_audit(source, client_ip, old_data, payload)


def update_keywords(new_value: str) -> None:
    _save_keywords_json(new_value, read_silent_keywords(), source="cli")


def update_silent_keywords(new_value: str) -> None:
    _save_keywords_json(read_keywords(), new_value, source="cli")


def keyword_web_settings(cfg: Dict[str, str]) -> Dict[str, str]:
    host = (cfg.get("WEB_HOST", DEFAULT_WEB_HOST) or DEFAULT_WEB_HOST).strip() or DEFAULT_WEB_HOST
    port = safe_int(cfg.get("WEB_PORT", str(DEFAULT_WEB_PORT)), DEFAULT_WEB_PORT)
    if port <= 0 or port > 65535:
        port = DEFAULT_WEB_PORT
    # Web 端修改关键词的服务端鉴权 PIN 固定为 0819。
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
        with _STATE_WRITE_LOCK:
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

    def ntfy_send(self, content: str, priority: Optional[str] = None) -> bool:
        url = (self.config.get("NTFY_URL", "http://127.0.0.1:8083") or "http://127.0.0.1:8083").rstrip("/")
        topic = (self.config.get("NTFY_TOPIC", "node") or "node").strip().strip("/")
        username = self.config.get("NTFY_USERNAME", "")
        password = self.config.get("NTFY_PASSWORD", "")
        if priority is None:
            priority = (self.config.get("NTFY_PRIORITY", "3") or "3").strip()
        if priority not in {"1", "2", "3", "4", "5"}:
            priority = "3"
        # 夜间静默规则放在最终发送层：覆盖普通、手动、测试以及显式高优先级推送。
        # 上海时间 00:00-08:00 强制 Priority=1；08:00 后恢复调用方/配置原有优先级。
        if is_shanghai_quiet_hours():
            priority = "1"
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
        return self.ntfy_send(content)


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
        with _RSS_LOG_WRITE_LOCK:
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
        silent_matcher = KeywordMatcher(self.config.get("SILENT_KEYWORDS", ""))
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
            silent_hit = silent_matcher.match(title)
            display_hit = hit or silent_hit
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
                "matched": bool(display_hit),
                "hit": display_hit,
                "sent": sent,
                "push_status": push_status if display_hit else "",
                "checked_at": now_value,
                "first_seen_at": str(old_all.get("first_seen_at") or now_value),
            }
            new_all.append(row)

            if display_hit:
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
        silent_matcher = KeywordMatcher(self.config.get("SILENT_KEYWORDS", ""))
        data = self._load_rss_log_data()

        if not data.get("all_logs"):
            # 兼容首次升级：从状态缓存生成 RSS 全部日志，并同步生成命中日志。
            all_logs: List[Dict[str, object]] = []
            hit_logs: List[Dict[str, object]] = []
            for entry in reversed(self.state.latest_entries(MAX_RSS_LOG_ENTRIES)):
                id_ = str(entry.get("id", ""))
                title = str(entry.get("title", ""))
                hit = matcher.match(title)
                silent_hit = silent_matcher.match(title)
                display_hit = hit or silent_hit
                sent, push_status = self._push_status_for_id(id_, fallback_sent=bool(entry.get("sent", False)))
                row = {
                    "id": id_,
                    "title": title,
                    "url": str(entry.get("url", "")),
                    "matched": bool(display_hit),
                    "hit": display_hit,
                    "sent": sent,
                    "push_status": push_status if display_hit else "",
                    "checked_at": str(entry.get("seen_at") or now_str()),
                    "first_seen_at": str(entry.get("seen_at") or ""),
                }
                all_logs.append(row)
                if display_hit:
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
            silent_hit = silent_matcher.match(title)
            display_hit = hit or silent_hit
            row["matched"] = bool(display_hit)
            row["hit"] = display_hit
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
        self.state.entries.clear()
        self.state.save()

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

    def _collect_matches_for(self, raw_keywords: str, window: int, mark_sent: bool, tag: str = "node") -> Tuple[str, List[str]]:
        matcher = KeywordMatcher(raw_keywords)
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
                f"🎯{tag}:【{hit}】",
                f"📆时间: {now_time}",
                f"🔖标题: {title}",
                f"🧬链接: {entry.get('url', '')}",
                "",
            ])
            ids_to_mark.append(str(entry.get("id", "")))
        return "\n".join(lines).rstrip(), ids_to_mark

    def _collect_matches(self, window: int, mark_sent: bool) -> Tuple[str, List[str]]:
        self.reload_config()
        return self._collect_matches_for(self.config.get("KEYWORDS", ""), window, mark_sent)

    def _collect_silent_matches(self, window: int, mark_sent: bool) -> Tuple[str, List[str]]:
        self.reload_config()
        return self._collect_matches_for(self.config.get("SILENT_KEYWORDS", ""), window, mark_sent, tag="node🔕")

    def _mark_sent(self, ids: List[str]) -> None:
        changed = False
        for id_ in ids:
            entry = self.state.entries.get(id_)
            if entry and not entry.get("sent"):
                entry["sent"] = True
                changed = True
        if changed:
            self.state.save()

    def auto_push_once(self) -> int:
        text, ids_to_mark = self._collect_matches(MATCH_WINDOW, mark_sent=True)
        extra_lines, extra_ids = self._pending_hit_log_matches(exclude_ids=set(ids_to_mark))
        if extra_lines:
            text = (text + "\n\n" if text else "") + "\n".join(extra_lines).rstrip()
            ids_to_mark.extend(extra_ids)
        silent_text, silent_ids = self._collect_silent_matches(MATCH_WINDOW, mark_sent=True)
        total = 0
        failed = 0
        if text and ids_to_mark:
            if self.send_message(text):
                self._mark_sent(ids_to_mark)
                self._update_rss_push_status(ids_to_mark, "已推送")
                self.logger.event(f"[node] 自动推送成功 {len(ids_to_mark)} 条")
                total += len(ids_to_mark)
            else:
                self._update_rss_push_status(ids_to_mark, "推送失败")
                failed += 1
        if silent_text and silent_ids:
            if self.ntfy_send(silent_text, priority="1"):
                self._mark_sent(silent_ids)
                self._update_rss_push_status(silent_ids, "已推送")
                self.logger.event(f"[node] 静默关键词推送成功 {len(silent_ids)} 条")
                total += len(silent_ids)
            else:
                self._update_rss_push_status(silent_ids, "推送失败")
                failed += 1
        if total:
            return total
        if failed:
            return -1
        return 0

    def manual_push(self) -> int:
        text, ids_to_mark = self._collect_matches(MANUAL_PUSH_WINDOW, mark_sent=False)
        silent_text, silent_ids = self._collect_silent_matches(MANUAL_PUSH_WINDOW, mark_sent=False)
        if not text and not silent_text:
            return 0
        total = 0
        if text and ids_to_mark and self.send_message(text):
            total += len(ids_to_mark)
        if silent_text and silent_ids and self.ntfy_send(silent_text, priority="1"):
            total += len(silent_ids)
        return total if total else -1

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
        today = shanghai_now().strftime("%Y-%m-%d")
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

            try:
                status, changed = self.refresh_once()
                if self.logger.debug:
                    self.logger.info(f"[node] 本轮刷新状态={status} 变化={changed}")
                push_count = self.auto_push_once()
                if self.logger.debug:
                    self.logger.info(f"[node] 本轮推送结果={push_count}")
                self.trim_logs_if_needed(40, loop_count)
            except Exception as exc:
                import traceback
                self.logger.error(f"[node] 监控循环异常: {exc}")
                self.logger.error(traceback.format_exc())
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


_WEB_MONITOR: Optional[NodeMonitor] = None
_WEB_MONITOR_LOCK = threading.Lock()


def web_log_monitor() -> NodeMonitor:
    """日志接口复用的只读 monitor，避免每次轮询重建 Session 与重载状态。"""
    global _WEB_MONITOR
    with _WEB_MONITOR_LOCK:
        if _WEB_MONITOR is None:
            _WEB_MONITOR = NodeMonitor()
        _WEB_MONITOR.reload_config()
        _WEB_MONITOR.state.load()
        return _WEB_MONITOR


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

        def _send_skin(self) -> None:
            try:
                body = SKIN_FILE.read_bytes()
            except FileNotFoundError:
                self.send_error(404, "Skin file not found")
                return
            except Exception as exc:
                self.send_error(500, f"Skin file read failed: {exc}")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/css; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


        def _read_form(self) -> Dict[str, List[str]]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_REQUEST_SIZE:
                    return {}
                body = self.rfile.read(length).decode("utf-8", errors="ignore")
                return parse_qs(body, keep_blank_values=True)
            except Exception:
                return {}

        def do_GET(self):
            try:
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/node_skin.css":
                    self._send_skin()
                    return
                if parsed.path == "/api/runtime-status":
                    self._send_json({"ok": True, "enabled": is_run_enabled(), "server_time": now_str()})
                    return
                if parsed.path == "/api/rss-logs":
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    mode = (query.get("mode", ["all"])[0] or "all").strip().lower()
                    monitor = web_log_monitor()
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
                if parsed.path in {"/", "/keywords"}:
                    self.respond_page(read_keywords(), read_silent_keywords(), "", False)
                    return
                self._send_json({"ok": False, "message": "Not found"}, status=404)
            except Exception as exc:
                try:
                    self._send_json({"ok": False, "error": str(exc)}, status=500)
                except Exception:
                    pass

        def do_DELETE(self):
            try:
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/api/rss-logs":
                    NodeMonitor().clear_rss_logs()
                    self._send_json({"ok": True, "message": "RSS日志已清除", "server_time": now_str()})
                    return
                self._send_json({"ok": False, "message": "Not found"}, status=404)
            except Exception as exc:
                try:
                    self._send_json({"ok": False, "error": str(exc)}, status=500)
                except Exception:
                    pass

        def do_POST(self):
            try:
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
                if parsed.path == "/api/keywords-save":
                    form = self._read_form()
                    required = {"keywords", "silent_keywords", "pin"}
                    if not form or not required.issubset(form.keys()):
                        self._send_json({"ok": False, "message": "关键词保存请求不完整"}, status=400)
                        return
                    submitted_pin = (form.get("pin", [""])[0] or "").strip()
                    if submitted_pin != save_pin:
                        self._send_json({"ok": False, "message": "PIN码错误"}, status=403)
                        return
                    new_keywords = (form.get("keywords", [""])[0] or "").strip()
                    new_silent_keywords = (form.get("silent_keywords", [""])[0] or "").strip()
                    clear_all_confirmed = (form.get("clear_all_confirmed", [""])[0] or "").strip() == "1"
                    is_all_empty = not new_keywords and not new_silent_keywords
                    if is_all_empty and not clear_all_confirmed:
                        self._send_json({
                            "ok": False,
                            "code": "confirm_clear_all_required",
                            "message": "两类关键词均为空，必须再次确认彻底清空",
                        }, status=409)
                        return
                    try:
                        client_ip = self.client_address[0] if self.client_address else ""
                        _save_keywords_json(
                            new_keywords,
                            new_silent_keywords,
                            source="web-clear-all" if is_all_empty else "web",
                            client_ip=client_ip,
                            allow_all_empty=is_all_empty and clear_all_confirmed,
                        )
                        self._send_json({"ok": True, "message": "保存成功", "server_time": now_str()})
                    except ValueError as exc:
                        self._send_json({"ok": False, "message": str(exc)}, status=409)
                    except Exception as exc:
                        self._send_json({"ok": False, "message": f"保存失败: {exc}"}, status=500)
                    return

                # 未知 POST 一律拒绝，绝不能再落入关键词保存逻辑。
                self._send_json({"ok": False, "message": "Not found"}, status=404)
            except Exception as exc:
                try:
                    self._send_json({"ok": False, "error": str(exc)}, status=500)
                except Exception:
                    pass

        def log_message(self, fmt, *args):
            pass

        def version_string(self):
            return ""

        def respond_page(self, keywords: str, silent_keywords: str, message: str, editing: bool, status: int = 200):
            safe_keywords = html.escape(keywords, quote=True)
            safe_silent_keywords = html.escape(silent_keywords, quote=True)
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
  <title>node捕鲨</title>
  <link rel="stylesheet" href="/node_skin.css?v=20261006_shark_inline">
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div class="hero-line">
        <div>
          <h1 class="brand-title">node捕<span class="brand-shark" aria-hidden="true"><svg viewBox="0 0 360 380"><defs><linearGradient id="nodeSharkGold" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#f8c64f"/><stop offset=".45" stop-color="#d99218"/><stop offset="1" stop-color="#9a5a0c"/></linearGradient><filter id="nodeSharkGlow" x="-15%" y="-15%" width="130%" height="130%"><feGaussianBlur stdDeviation="1.25" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs><path d="M272 144L272 149L274 156L274 153L278 147L280 148L280 151L277 153L276 156L277 157L273 161L272 159L272 162L286 147L287 148L287 161L284 170L291 165L299 155L300 156L298 167L292 181L300 174L309 160L305 155L300 154L299 152L294 149L285 147L280 142L278 144ZM295 174L296 173L297 174L296 175ZM285 167L286 166L287 168L286 169ZM301 165L302 167L297 174L296 173L297 168ZM287 162L289 164L287 167L286 166ZM290 159L291 161L289 163L288 161ZM294 159L295 158L296 159L295 160ZM290 158L291 157L292 159L291 160ZM287 158L288 157L289 158L288 159ZM291 157L292 156L293 157L292 158ZM292 156L293 155L294 156L293 157ZM292 154L293 153L294 154L293 155ZM255 142L246 143L249 152L250 151L249 148L250 147L252 148L251 149ZM248 151L249 150L250 151L249 152ZM270 143L264 141L263 142L258 142L259 151L261 154L260 155ZM264 145L267 147L261 154L259 150L260 149L261 150ZM271 89L280 92L313 109L289 96ZM78 6L87 11L97 21L106 37L109 49L109 63L107 72L101 86L95 94L117 78L116 79L112 78L116 60L115 47L111 35L112 33L121 40L132 55L136 63L139 74L137 81L131 89L117 92L92 101L78 108L77 111L75 110L71 112L70 115L68 114L50 127L47 130L57 126L62 125L66 126L56 151L60 148L64 138L75 118L97 106L99 107L85 121L79 129L69 149L65 153L49 159L27 174L15 186L7 197L2 207L6 203L17 196L41 186L66 180L95 177L96 178L88 183L84 187L86 189L85 190L81 190L78 192L78 193L82 191L84 192L85 196L84 197L83 196L84 197L82 201L83 205L82 206L81 205L80 207L82 209L81 210L79 209L78 211L79 212L77 213L75 220L73 217L76 229L75 232L69 223L66 216L64 217L60 212L61 187L61 190L58 192L58 193L59 191L60 192L60 198L59 199L57 197L57 195L56 199L54 200L53 195L54 216L61 239L67 251L66 248L66 235L68 228L70 230L71 235L76 244L87 260L102 276L123 292L141 304L131 289L127 281L128 279L136 285L157 294L185 303L188 303L191 305L194 305L211 332L230 352L241 360L255 368L275 375L259 360L251 347L247 335L247 329L245 326L245 318L244 317L245 306L247 305L252 313L252 303L254 294L258 284L263 277L264 273L277 257L288 248L301 241L281 248L279 247L282 245L280 245L279 244L280 243L296 241L287 241L284 243L274 244L256 249L221 265L204 280L202 280L200 282L184 278L189 280L185 281L174 277L164 270L162 270L154 260L155 259L162 266L154 258L150 251L151 253L149 255L148 254L148 250L150 247L159 250L156 247L151 238L149 231L149 225L156 212L165 203L177 197L181 196L200 196L210 198L223 203L216 194L214 194L207 190L210 189L226 195L243 204L260 217L271 229L270 226L271 225L272 227L273 225L272 222L273 221L274 222L273 219L274 218L275 219L278 210L279 197L275 204L270 208L269 211L266 208L267 206L268 207L270 201L269 202L268 201L267 193L272 189L273 190L271 199L273 188L265 195L262 196L262 198L265 202L264 204L256 193L257 191L260 194L261 193L264 182L264 176L257 182L251 184L250 183L251 176L248 174L248 170L251 167L252 168L252 174L252 166L248 170L241 173L239 171L239 164L237 163L238 160L240 159L230 163L228 160L211 156L216 151L225 145L242 138L269 137L290 142L305 149L307 151L310 149L314 152L312 153L313 155L312 154L315 152L317 154L316 158L313 159L313 164L311 167L332 152L354 131L352 130L349 131L347 129L348 128L347 129L346 127L326 116L330 119L328 120L290 100L281 97L277 94L272 93L263 88L264 87L269 88L267 87L264 87L250 82L248 82L250 83L249 84L246 84L236 81L227 80L226 79L227 78L232 78L227 78L226 77L219 77L218 76L210 76L215 76L216 77L215 78L190 77L189 76L190 75L208 75L199 74L185 57L175 47L153 29L130 17L111 10L94 6ZM269 372L270 371L271 372L270 373ZM248 343L249 342L250 343L249 344ZM247 340L248 339L249 340L248 341ZM246 337L247 336L248 338L247 339ZM245 333L246 332L247 333L246 334ZM244 331L245 330L246 331L245 332ZM244 328L245 327L246 328L245 329ZM220 311L221 310L222 312L221 313ZM197 307L198 306L199 307L198 308ZM212 300L214 303L212 307L207 310L208 312L206 313L202 309L203 307L200 306L204 305L205 302L206 303L210 302ZM198 295L201 294L203 296L200 297ZM243 287L244 286L245 287L244 288ZM189 281L190 280L193 281L192 282ZM126 279L127 278L128 279L127 280ZM253 277L254 276L255 277L254 278ZM254 276L255 275L256 276L255 277ZM220 268L221 267L222 268L221 269ZM221 267L222 266L224 267L223 268ZM253 268L249 277L250 276L254 279L252 282L248 281L245 287L243 286L238 294L235 292L236 295L233 297L232 296L233 294L232 294L229 299L227 296L226 297L220 297L219 296L222 290L229 281L242 269L248 265L250 265ZM254 265L255 264L256 265L255 266ZM255 264L256 263L257 264L256 265ZM232 262L225 267L223 266L230 261ZM231 261L232 260L234 261L233 262ZM234 260L235 259L236 260L235 261ZM236 259L237 258L238 259L237 260ZM153 259L154 258L155 259L154 260ZM238 258L239 257L240 258L239 259ZM240 257L241 256L242 257L241 258ZM93 257L94 256L95 257L94 258ZM151 256L152 255L154 258L152 259ZM141 255L142 254L143 256L142 257ZM150 254L151 253L152 255L151 256ZM140 254L141 253L142 254L141 255ZM249 253L250 252L251 253L250 254ZM108 253L109 252L111 253L110 254ZM251 252L252 251L253 252L252 253ZM105 249L106 248L107 249L106 250ZM277 248L278 247L280 248L279 249ZM139 242L140 241L141 242L140 243ZM137 237L139 240L138 243L139 242L142 245L142 250L140 254L136 248L136 238ZM75 232L76 231L77 232L76 233ZM271 225L272 224L273 225L272 226ZM89 222L90 221L91 222L90 223ZM65 219L66 218L67 219L66 220ZM91 214L92 215L91 219L90 218ZM89 212L90 211L91 213L90 214ZM81 210L82 209L83 211L82 212ZM80 207L81 206L82 207L81 208ZM264 204L265 203L267 206L266 207ZM278 199L279 203L277 213L275 217L274 216L274 205ZM210 195L211 194L212 195L211 196ZM250 194L251 193L252 195L251 196ZM209 194L210 193L211 194L210 195ZM249 193L250 192L251 193L250 194ZM208 193L209 192L210 193L209 194ZM248 192L249 191L250 192L249 193ZM205 189L206 188L207 189L206 190ZM154 189L155 188L156 189L155 190ZM167 183L168 182L169 184L168 185ZM164 182L165 181L166 182L165 183ZM93 180L94 179L95 181L94 182ZM263 177L264 182L262 187L257 182ZM113 172L114 171L115 172L114 173ZM70 170L71 169L72 170L71 171ZM71 169L72 168L73 169L72 170ZM234 168L235 167L236 168L235 169ZM231 166L233 165L235 167L233 168ZM230 165L231 164L232 165L231 166ZM227 163L229 162L231 164L229 165ZM224 162L225 161L228 162L227 163ZM92 162L93 161L95 162L94 163ZM87 163L89 161L91 162L90 164ZM131 160L132 159L133 160L132 161ZM204 159L205 158L206 159L205 160ZM209 153L210 157L206 159L205 158ZM130 156L135 153L136 154L137 152L139 152L141 150L144 150L148 152L152 151L154 154L157 155L156 156L142 156L141 157L131 157ZM307 149L308 148L309 149L308 150ZM304 148L305 147L307 148L306 149ZM303 147L304 146L305 147L304 148ZM326 145L327 144L328 145L327 146ZM324 144L325 143L326 144L325 145ZM325 143L326 142L328 143L327 144ZM89 140L90 139L91 140L90 141ZM335 140L337 138L340 139L337 141ZM70 149L70 147L72 146L74 142L75 143L77 141L79 142L82 138L88 138L89 141L99 140L109 142L105 144L101 144L87 148L80 148L71 150ZM339 138L340 137L341 138L340 139ZM343 134L344 132L346 133L344 135ZM341 133L342 135L340 137L334 138L335 143L333 145L329 144L331 142L329 143L327 142L330 139L331 134L332 135L336 132ZM341 130L342 129L347 129L348 130L347 131L342 131ZM313 130L314 129L316 131L314 132ZM334 129L335 128L338 129L337 130ZM322 128L323 127L325 128L324 129ZM161 126L162 125L163 127L162 128ZM339 125L340 124L342 125L341 126ZM331 125L332 124L333 125L332 126ZM320 125L321 124L325 125L328 124L333 128L331 129ZM313 124L314 123L315 124L314 125ZM100 124L101 123L102 124L101 125ZM101 123L102 122L103 123L102 124ZM333 122L334 121L336 122L335 123ZM332 121L333 120L334 121L333 122ZM58 121L59 120L60 121L59 122ZM330 120L331 119L332 120L331 121ZM61 119L62 118L63 119L62 120ZM64 117L65 116L66 117L65 118ZM211 116L212 115L213 116L212 117ZM151 116L152 115L153 116L152 117ZM289 115L290 114L291 115L290 116ZM154 115L155 114L157 115L156 116ZM67 115L68 114L69 115L68 116ZM288 114L289 113L290 114L289 115ZM70 113L71 112L72 113L71 114ZM285 112L287 111L289 113L287 114ZM72 112L73 111L74 112L73 113ZM74 111L75 110L76 111L75 112ZM281 110L282 109L283 110L282 111ZM170 110L171 109L172 110L171 111ZM77 109L78 108L79 109L78 110ZM272 108L273 107L274 108L273 109ZM79 108L80 107L81 108L80 109ZM271 107L272 106L273 107L272 108ZM98 106L99 105L100 106L99 107ZM201 105L202 104L205 105L204 106ZM202 106L189 110L186 112L184 111L189 104L190 107L192 105L194 106L196 103L198 103ZM189 104L190 103L191 104L190 105ZM274 103L275 102L277 103L276 104ZM245 103L246 102L248 103L247 104ZM211 103L212 102L213 103L212 104ZM243 102L244 101L245 102L244 103ZM209 102L210 101L211 102L210 103ZM189 101L190 102L183 110L184 112L180 120L176 135L177 152L180 161L185 170L183 171L165 168L163 170L159 170L165 171L184 178L200 186L208 192L203 195L191 190L181 189L179 187L177 188L169 184L170 183L168 182L170 181L165 181L164 182L159 181L158 182L147 183L128 191L120 197L110 209L106 221L106 230L108 236L108 231L113 220L121 212L126 209L127 210L126 217L127 218L128 229L131 238L140 254L141 258L146 262L155 273L172 286L170 287L149 280L123 265L107 249L101 241L95 228L93 229L90 225L92 222L94 226L91 213L92 202L95 193L101 183L108 175L124 171L131 166L120 172L118 172L117 170L116 172L115 171L115 169L117 167L116 168L115 167L113 169L109 169L108 168L109 167L107 170L99 168L89 169L88 170L86 169L78 171L74 170L76 167L80 166L82 168L83 165L86 165L87 166L86 167L88 167L92 165L93 163L105 160L110 160L117 158L126 158L127 160L130 159L132 161L136 160L138 162L140 160L143 161L148 159L152 156L158 156L154 152L153 149L150 149L134 136L131 133L132 132L130 133L117 133L116 132L134 117L151 109L152 112L150 113L151 115L150 116L149 115L150 117L149 118L148 117L147 121L147 131L149 138L153 145L152 144L151 133L154 120L158 113L166 105L170 103L171 104L169 106L170 105L171 106L171 109L168 111L167 110L168 108L165 113L167 110L168 111L170 110L171 112L169 114L164 115L161 126L161 139L167 155L166 152L166 135L169 124L172 117L178 109ZM143 268L144 272L149 274L151 277L153 278L154 277L150 273L145 271ZM277 101L278 100L279 102L278 103ZM267 102L271 100L274 104L279 106L282 105L284 108L281 110L278 109ZM264 101L265 100L267 101L266 102ZM208 100L209 102L207 104L206 102ZM189 101L190 100L191 101L190 102ZM262 100L263 99L264 100L263 101ZM213 103L215 99L218 103L217 104ZM277 99L278 98L279 99L278 100ZM260 99L261 98L262 99L261 100ZM276 98L277 97L278 98L277 99ZM275 97L276 96L277 97L276 98ZM250 95L251 94L252 95L251 96ZM115 95L116 94L117 95L116 96ZM116 94L117 93L119 94L118 95ZM251 92L252 93L249 95L248 94ZM245 93L246 92L247 93L246 94ZM124 92L125 91L126 92L125 93ZM96 92L97 91L98 92L97 93ZM260 87L261 86L264 87L263 88ZM253 85L257 84L261 86L257 87ZM201 84L202 83L212 84L232 89L230 89L229 88L230 87L235 88L240 87L245 92L243 93L256 97L268 103L271 106L270 108L272 110L285 117L282 114L283 112L294 118L302 125L296 116L297 115L309 121L313 124L312 125L317 124L320 126L317 129L313 128L314 129L313 130L311 128L310 129L307 128L308 129L307 131L302 129L296 129L292 126L284 128L271 127L270 126L273 125L267 122L260 114L261 119L264 122L262 123L258 119L254 112L252 104L245 98L244 99L241 98L243 102L242 103L239 102L238 104L236 104L233 101L232 102L230 100L233 103L232 105L230 105L223 100L220 104ZM266 110L267 117L271 121L276 123L285 122L279 118L277 119L274 114ZM269 114L270 113L273 114L280 121L277 123L273 122L270 118ZM149 81L150 80L151 81L150 82ZM157 79L158 78L160 79L159 80ZM223 78L224 77L226 78L225 79ZM217 78L218 77L219 78L218 79ZM159 78L160 77L164 78L163 79ZM199 74L198 75L178 76L166 78L164 76L173 71L175 72L177 70L183 70L186 68ZM108 65L109 64L110 65L109 66ZM177 63L179 62L182 64L179 65ZM109 60L110 59L111 61L110 62ZM171 56L172 55L173 56L172 57ZM110 55L111 56L110 59L109 58ZM181 55L182 54L183 55L182 56ZM170 55L171 54L172 55L171 56ZM177 53L178 52L179 53L178 54ZM176 52L177 51L178 52L177 53ZM175 51L176 50L177 51L176 52ZM165 50L167 49L168 51L167 52ZM164 49L165 48L166 49L165 50ZM130 24L134 23L136 25L139 25L141 23L152 29L169 42L176 49L175 50L176 53L175 54L169 49L162 48L161 46L146 34ZM160 40L159 42L162 44L159 41ZM154 34L155 36L154 37L155 38L156 36L157 37ZM129 23L130 22L131 23L130 24Z" fill="url(#nodeSharkGold)" fill-rule="evenodd" stroke="#4e2807" stroke-width="2.7" stroke-linejoin="round" filter="url(#nodeSharkGlow)"/><path d="M265 366L271 372L269 374L276 376ZM249 307L253 314L253 306L252 309ZM144 269L145 273L150 275L152 278L155 278ZM288 250L277 257L271 256L250 266L253 269L250 278L253 278L254 281L249 282L239 295L236 293L236 297L233 295L231 298L222 298L221 296L221 308L219 310L214 305L212 309L205 312L205 305L211 302L185 297L180 294L179 296L186 299L188 302L184 303L176 301L195 306L209 328L205 322L205 317L209 320L217 332L235 349L239 351L233 327L232 315L239 305L246 302L252 286L263 270L267 266L269 267L265 275L277 259ZM177 199L167 202L160 210L169 202ZM273 228L271 229L268 226L253 201L239 185L232 182L230 187L227 188L204 177L203 178L208 186L207 188L200 187L181 178L207 191L208 194L205 196L192 191L182 190L180 188L178 189L172 186L171 182L152 183L139 187L126 194L117 202L111 210L107 222L107 231L109 237L109 232L114 221L125 211L128 212L127 218L128 214L140 200L145 200L156 196L166 197L173 192L182 192L187 194L186 196L179 198L201 197L224 204L217 195L212 193L214 191L244 205L261 218L271 230ZM114 213L115 216L111 224L109 225L109 216ZM168 169L160 171L167 173L166 171ZM10 196L3 208L18 197L42 187L67 181L94 178L95 180L85 188L86 190L79 193L84 193L85 199L83 202L84 205L82 206L76 220L74 219L74 215L76 225L75 229L72 227L67 217L65 218L61 213L62 188L62 191L59 193L61 195L61 198L59 199L58 196L57 200L55 201L54 196L55 217L62 240L68 252L67 236L68 231L70 230L77 245L97 271L103 277L86 257L87 255L111 279L109 281L105 278L142 305L137 298L135 300L123 288L121 283L122 280L124 280L135 294L129 284L130 281L137 286L147 290L140 285L141 282L133 275L134 273L153 285L164 289L170 287L170 285L160 277L170 286L167 287L155 283L138 275L115 258L120 263L119 265L110 260L104 252L105 247L108 249L102 242L96 229L93 229L95 227L92 210L98 190L109 176L125 172L132 167L122 172L118 171L118 168L114 170L111 170L110 168L106 171L100 169L89 171L87 170L88 168L93 166L88 167L86 171L84 171L83 168L80 168L82 168L83 170L79 172L74 170L47 180L24 192L10 202L7 201ZM64 239L66 238L67 241L65 242ZM98 186L99 188L95 193L94 189ZM152 158L140 161L128 161L137 161L139 163L141 161L144 162ZM297 151L301 157L305 157L308 160L308 165L310 161L308 158L301 155ZM178 149L178 153L185 170L186 169L180 159ZM284 146L288 150L288 153L291 150L295 150L288 149ZM247 145L248 148L251 143L253 143L255 146L256 143L250 143ZM275 139L265 138L252 134L243 135L228 142L210 157L217 158L214 158L213 156L221 149L243 139ZM279 129L299 134L309 138L312 141L312 147L310 149L285 142L298 146L308 152L311 150L314 152L314 156L314 154L316 153L317 158L314 160L314 165L312 168L318 164L316 165L315 161L320 154L334 148L335 150L328 157L355 132L353 131L351 134L345 135L324 130L322 128L308 129L308 132L297 130L293 127ZM342 134L343 136L341 138L335 139L336 144L332 146L332 143L330 142L331 137L337 133ZM76 120L69 124L56 128L54 126L48 131L58 127L67 127L57 152L61 149L69 131ZM157 118L153 123L151 135L149 134L148 130L150 139L154 146L152 134L153 127ZM261 115L262 120L267 125L274 126L268 123ZM177 113L168 121L166 147L164 146L163 142L168 156L168 131L173 118ZM271 109L286 118L282 113L272 108ZM259 119L255 113L253 105L244 97L242 99L244 103L240 103L239 105L231 101L234 104L233 106L231 106L222 101L223 103L216 108L200 110L188 116L184 114L185 110L179 128L183 123L184 133L182 139L184 141L186 140L187 134L190 130L193 131L194 135L202 132L207 135L220 133L223 130L223 126L220 123L221 117L218 116L219 113L235 114L246 112ZM144 91L117 102L97 116L82 132L82 128L93 115L80 130L68 152L74 150L72 150L71 148L78 142L80 143L83 139L89 139L90 142L104 142L97 141L96 138L107 133L117 133L134 119L126 123L121 123L120 120L127 113L135 109L147 99L148 97L144 96ZM127 91L93 102L97 101L98 104L81 116L99 107L105 101ZM103 90L101 91L100 89L96 95ZM116 63L113 73L114 81L109 86L118 79L113 79ZM79 7L88 12L98 22L107 38L109 49L108 39L111 39L116 52L117 61L116 48L112 35L114 34L128 48L137 64L139 71L139 79L135 87L142 80L150 82L159 79L162 80L163 78L169 79L166 78L167 75L186 70L175 67L156 68L152 66L143 66L139 61L144 52L153 52L153 45L147 38L117 20L89 11L86 9L87 7Z" fill="#603207" opacity=".78" fill-rule="evenodd"/><path d="M243 312L237 322L240 338L246 347L251 360L257 366L266 370L254 355L249 344L249 340L247 339L248 336ZM154 290L160 294L172 297ZM130 221L134 241L137 247L138 244L142 245L141 247L143 248L143 251L140 253L155 271L165 278L178 284L184 292L201 298L210 299L217 303L219 292L224 285L243 267L244 263L251 263L266 255L286 249L293 245L285 248L279 245L260 250L235 261L234 263L230 263L230 265L227 267L225 266L218 271L212 278L224 272L228 275L226 283L217 294L214 294L207 289L205 284L191 283L190 281L182 281L173 277L173 274L170 275L163 271L155 262L155 259L152 259L151 253L149 252L150 246L148 243L148 231L151 220L158 208L150 214L148 213L147 208L139 209L137 216ZM200 296L202 295L203 297L201 298ZM268 195L266 197L267 202L269 202ZM172 172L177 174L175 172ZM305 160L301 162L299 168L301 170L298 171L298 175L303 171L306 166ZM210 161L206 167L206 170L214 171L221 175L227 174L238 181L255 200L268 219L270 225L272 226L276 218L275 216L277 215L275 214L275 207L270 213L266 210L257 194L257 192L263 188L260 184L258 184L255 188L250 184L249 180L251 177L249 175L249 171L245 175L243 175L239 172L238 163L232 165L220 160ZM295 152L292 152L289 155L289 166L298 157L298 155ZM282 147L279 146L275 148L275 157L278 157L283 152ZM280 148L281 152L276 157L275 154ZM266 144L261 147L262 151L264 147L267 147ZM155 155L152 151L132 136L120 136L105 146L84 151L72 152L62 159L54 160L47 163L38 169L13 196L45 178L74 167L88 165L90 162L93 164L94 162L97 163L116 158L151 157L133 157L134 155L137 155L142 151L153 153ZM68 160L71 158L73 159L72 162L69 162ZM276 118L280 123L281 122ZM191 153L198 159L203 160L211 152L230 138L246 132L261 133L276 138L303 144L304 142L298 137L291 136L268 128L258 121L239 117L233 119L233 121L237 125L237 127L228 134L213 138L201 146L197 146L194 144L191 149ZM270 114L269 117L273 121L270 117ZM89 107L80 110L59 124L75 118ZM217 102L208 94L202 92L192 92L189 94L184 94L179 90L176 91L177 96L174 99L168 97L164 100L157 101L153 104L148 105L145 109L135 113L132 116L136 116L147 109L151 109L152 119L156 117L167 105L169 105L172 108L171 111L169 109L168 111L171 113L167 116L175 113L188 102L190 103L189 106L191 108L193 106L195 107L197 104L202 106L201 108L189 112L199 108L216 105L215 103ZM147 86L138 87L133 91L124 94L106 104L103 108L116 99ZM159 84L167 88L177 88L188 83L201 82L210 83L230 89L242 89L246 94L251 94L259 99L267 101L269 104L270 102L273 102L274 107L291 115L296 119L299 117L303 117L328 129L344 132L349 131L346 128L336 124L335 122L331 120L329 121L319 116L319 113L317 112L314 113L291 101L273 94L269 91L269 89L251 83L247 85L247 82L244 82L242 84L242 81L238 83L237 80L233 82L231 79L214 79L213 77L202 78L201 76L198 76L197 78L185 78ZM327 127L330 126L331 128L328 129ZM277 107L284 107L285 109L279 110ZM112 52L112 62L110 70L114 63L114 56ZM149 28L158 34L157 36L155 35L155 38L158 38L157 36L159 35ZM94 9L116 17L148 36L158 46L158 49L162 54L159 60L194 70L188 61L172 45L176 49L175 53L170 50L163 49L159 44L166 44L164 45L161 41L158 44L133 26L134 24L137 26L140 26L142 24L143 25L134 20L115 13Z" fill="#f4b234" opacity=".42" fill-rule="evenodd"/><path d="M243 325L241 330L243 337L247 342L246 333ZM193 291L195 294L202 295L204 297L209 297L207 294L197 290ZM233 264L228 267L233 265ZM283 246L272 248L260 252L256 255L265 254L276 250ZM136 225L134 227L135 239L137 244L142 245L141 247L143 248L142 254L155 268L178 281L188 285L191 285L188 282L182 281L173 277L160 268L154 260L152 259L152 257L149 255L145 239L141 232L141 228L139 225ZM275 209L273 213L272 218L273 219L275 216ZM267 198L269 200L268 199L269 197ZM260 184L259 187L261 188L262 186ZM249 173L248 175L250 176ZM304 163L302 164L301 166L302 169L300 171L304 167ZM217 163L239 179L259 202L254 191L249 186L245 179L238 174L236 167L230 166L228 164L222 162ZM295 154L291 155L290 157L291 163L290 164L296 158ZM281 148L278 148L276 150L276 153L279 148L281 149L281 152L278 154L278 156L282 151ZM126 155L127 156L133 156L137 155L138 153L140 153L142 151L152 153L142 147L136 147L131 149ZM127 145L125 144L123 145L112 144L110 146L108 146L99 151L99 154L96 157L86 163L95 162L108 158L110 156L109 155L110 152L119 149L124 149L127 147ZM222 140L218 140L211 143L204 152L207 153L218 145ZM249 129L264 131L280 137L286 137L271 131L267 131L258 124L254 128ZM160 108L157 108L155 110L153 116L157 114ZM184 101L175 103L170 112L172 113L174 112ZM191 98L193 101L191 108L193 106L195 107L197 104L202 106L215 103L211 99L207 98L205 99L199 97ZM197 79L209 80L215 83L232 88L242 89L244 92L250 94L252 93L253 95L258 96L269 102L273 102L277 106L284 107L285 109L283 110L288 112L293 116L296 116L299 113L310 115L313 118L314 121L322 125L330 126L334 129L345 130L317 114L264 89L258 88L252 85L247 85L227 80L204 79L203 78ZM160 46L173 62L178 64L180 63L183 66L189 67L189 65L177 51L174 53L170 50L163 49ZM160 42L163 45L166 44L164 45L161 41ZM155 35L155 38L156 39L158 38ZM124 19L132 24L140 26L139 24L133 21Z" fill="#ffd968" opacity=".67" fill-rule="evenodd"/><path d="M138 236L137 237L139 240L138 243L139 242L142 245L142 251L144 251L144 246ZM139 242L140 241L141 242L140 243ZM134 153L136 154L137 152L139 152L141 150L144 150L148 152L144 150L138 150ZM326 123L329 125L335 126L332 124ZM331 125L332 124L333 125L332 126ZM192 105L195 105L196 103L198 103L194 103ZM273 94L274 97L270 99L270 100L274 103L276 102L277 105L279 106L282 105L284 108L289 111L291 111L289 106L290 105L295 105L294 103L283 97L281 97L276 94ZM277 101L278 100L279 102L278 103ZM277 99L278 98L279 99L278 100ZM276 98L277 97L278 98L277 99ZM275 97L276 96L277 97L276 98ZM228 82L238 88L240 87L242 89L244 89L244 85L240 83ZM165 48L168 50L168 52L170 53L176 60L180 62L181 61L180 58L176 53L175 54L169 49ZM160 40L159 42L162 44L162 43L159 41ZM154 34L155 36L154 37L155 38L156 36L157 37Z" fill="#fff0a2" opacity=".74" fill-rule="evenodd"/></svg></span></h1>
        </div>
        <div class="switch-group">
          <label id="runSwitchWrap" class="switch-wrap on" title="开启或暂停自动监控和推送">
            <span id="runLabel" class="switch-label">运行</span>
            <span class="switch"><input id="runToggle" type="checkbox" checked><span class="slider"></span></span>
          </label>
        </div>
      </div>
    </section>

    <section class="card keyword-card">
      <form id="keywordForm" autocomplete="off" onsubmit="return false;">
        <div class="keyword-header">
          <h2 class="keyword-title">关键词 <span class="title-rule">采用空格间隔，&amp;表示与关系</span></h2>
          <button id="actionBtn" type="button" onclick="handleAction()">__ACTION_LABEL__</button>
        </div>
          <textarea id="keywords" name="keywords" spellcheck="false" __READONLY__ placeholder="例如：抽奖 甲&乙 amd&7950x&盒装&国行">__SAFE_KEYWORDS__</textarea>
        <div class="keyword-header silent-header">
          <h2 class="keyword-title">静默关键词 <span class="title-rule">采用空格间隔，&amp;表示与关系</span></h2>
        </div>
          <textarea id="silent_keywords" name="silent_keywords" spellcheck="false" __READONLY__ placeholder="例如：开机 测速&结果">__SAFE_SILENT_KEYWORDS__</textarea>
        <div id="keywordMessage" class="__MSG_CLASS__">__SAFE_MESSAGE__</div>
      </form>
    </section>

    <section id="logCard" class="card log-card">
      <div class="log-head">
        <h2>RSS日志 <span class="log-meta">最新20条</span></h2>
        <label id="logSwitchWrap" class="switch-wrap" title="显示或隐藏RSS日志">
          <span id="logLabel" class="switch-label">日志</span>
          <span class="switch"><input id="logToggle" type="checkbox"><span class="slider"></span></span>
        </label>
      </div>
      <div id="logBody" class="log-body">
        <div class="log-meta" id="logMeta">等待刷新</div>
        <div class="log-actions">
          <div class="log-left">
            <button id="btnAll" type="button" class="active" onclick="setMode('all')">RSS全部</button>
            <button id="btnHits" type="button" class="secondary" onclick="setMode('hits')">命中</button>
          </div>
          <button type="button" class="danger" onclick="clearLogs()">清除</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>标题</th>
                <th style="width:112px;">命中词</th>
                <th style="width:132px;">时间</th>
                <th style="width:82px;">结果</th>
                <th style="width:102px;">推送</th>
              </tr>
            </thead>
            <tbody id="rssLogBody"><tr><td class="empty" colspan="6"></td></tr></tbody>
          </table>
        </div>
      </div>
    </section>
  </div>
  <script>
    let logMode = localStorage.getItem('nodeRssLogMode') || 'all';
    let logTimer = null;
    let runStatusTimer = null;
    let pendingKeywordPin = '';

    function setKeywordMessage(message, ok) {
      const el = document.getElementById('keywordMessage');
      if (!el) return;
      el.textContent = message || '';
      el.className = message ? (ok ? 'msg ok' : 'msg err') : 'msg';
    }

    function handleAction() {
      const textarea = document.getElementById('keywords');
      const silentTextarea = document.getElementById('silent_keywords');
      const actionBtn = document.getElementById('actionBtn');

      if (textarea.hasAttribute('readonly')) {
        textarea.removeAttribute('readonly');
        silentTextarea.removeAttribute('readonly');
        actionBtn.textContent = '保存';
        setKeywordMessage('', true);
        setTimeout(() => {
          textarea.focus();
          textarea.setSelectionRange(textarea.value.length, textarea.value.length);
        }, 50);
        return;
      }
      openPinModal();
    }

    function openPinModal() {
      const modal = document.getElementById('confirmModal');
      const pinInput = document.getElementById('pinInput');
      document.getElementById('confirmMessage').textContent = '请输入 PIN 码以确认保存关键词修改';
      document.getElementById('pinError').textContent = '';
      pinInput.value = '';
      modal.classList.remove('hidden');
      setTimeout(() => pinInput.focus(), 50);
    }

    async function submitKeywords() {
      const textarea = document.getElementById('keywords');
      const silentTextarea = document.getElementById('silent_keywords');
      const pinInput = document.getElementById('pinInput');
      const pinError = document.getElementById('pinError');
      const pin = String(pinInput.value || '').trim();

      if (!/^\\d{4}$/.test(pin)) {
        pinError.textContent = '请输入4位数字 PIN';
        pinInput.focus();
        return;
      }

      // 先发给后端校验 PIN。若两类关键词都为空，后端会在 PIN 正确后返回二次确认要求。
      await saveKeywordsRequest(pin, false);
    }

    async function saveKeywordsRequest(pin, clearAllConfirmed) {
      const textarea = document.getElementById('keywords');
      const silentTextarea = document.getElementById('silent_keywords');
      const actionBtn = document.getElementById('actionBtn');
      const pinError = document.getElementById('pinError');
      const clearError = document.getElementById('clearAllError');

      const body = new URLSearchParams();
      body.set('keywords', textarea.value || '');
      body.set('silent_keywords', silentTextarea.value || '');
      body.set('pin', pin);
      if (clearAllConfirmed) body.set('clear_all_confirmed', '1');

      try {
        const res = await fetch('/api/keywords-save', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
          body: body.toString(),
          cache: 'no-store'
        });
        let data = {};
        try { data = await res.json(); } catch (err) {}
        if (!res.ok || !data.ok) {
          // 只有 PIN 已被服务端验证通过后，才允许进入“彻底清空”的第二个弹窗。
          if (!clearAllConfirmed && data && data.code === 'confirm_clear_all_required') {
            pendingKeywordPin = pin;
            closeConfirmModal(false);
            openClearAllModal();
            return;
          }
          const msg = (data && data.message) ? data.message : '保存失败';
          if (clearAllConfirmed) {
            if (clearError) clearError.textContent = msg;
          } else {
            if (pinError) pinError.textContent = msg;
            const currentPinInput = document.getElementById('pinInput');
            if (currentPinInput) currentPinInput.select();
          }
          return;
        }

        pendingKeywordPin = '';
        closeConfirmModal();
        closeClearAllModal();
        textarea.setAttribute('readonly', 'readonly');
        silentTextarea.setAttribute('readonly', 'readonly');
        actionBtn.textContent = '修改';
        setKeywordMessage(clearAllConfirmed ? '全部关键词已清空' : '保存成功', true);
      } catch (err) {
        const msg = '保存请求失败，请重试';
        if (clearAllConfirmed) {
          if (clearError) clearError.textContent = msg;
        } else if (pinError) {
          pinError.textContent = msg;
        }
      }
    }

    function openClearAllModal() {
      const modal = document.getElementById('clearAllModal');
      const error = document.getElementById('clearAllError');
      if (error) error.textContent = '';
      modal.classList.remove('hidden');
    }

    async function confirmClearAllKeywords() {
      const pin = pendingKeywordPin;
      if (!pin) {
        closeClearAllModal();
        setKeywordMessage('PIN 验证状态已失效，请重新保存', false);
        return;
      }
      await saveKeywordsRequest(pin, true);
    }

    function closeClearAllModal() {
      const modal = document.getElementById('clearAllModal');
      const error = document.getElementById('clearAllError');
      if (error) error.textContent = '';
      if (modal) modal.classList.add('hidden');
    }

    function closeConfirmModal(clearPendingPin = true) {
      const modal = document.getElementById('confirmModal');
      const pinInput = document.getElementById('pinInput');
      const pinError = document.getElementById('pinError');
      if (pinInput) pinInput.value = '';
      if (pinError) pinError.textContent = '';
      if (clearPendingPin) pendingKeywordPin = '';
      modal.classList.add('hidden');
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
        if (isLogVisible()) fetchLogs()
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
      const body = document.getElementById('logBody');
      toggle.checked = Boolean(visible);
      setSwitchLabelState('logSwitchWrap', visible);
      body.classList.toggle('show', Boolean(visible));
      localStorage.setItem('nodeRssLogVisible', visible ? 'true' : 'false');
      if (visible) {
        if (shouldFetch) fetchLogs();
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
      if (isLogVisible()) fetchLogs()
    }

    function renderLogs(logs) {
      const body = document.getElementById('rssLogBody');
      if (!logs || logs.length === 0) {
        body.innerHTML = '<tr><td class="empty" colspan="5">暂无RSS日志</td></tr>';
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
        const titleLink = url ? `<a class="title-link" href="${url}" target="_blank" rel="noopener noreferrer">${title}</a>` : title;
        return `<tr>
          <td class="title">${titleLink}</td>
          <td>${hit}</td>
          <td class="time">${compactTime(row.checked_at || row.first_seen_at || '')}</td>
          <td>${tag}</td>
          <td>${statusTag}</td>
        </tr>`;
      }).join('');
    }

    async function fetchLogs() {
      if (!isLogVisible()) {
        setLogVisible(true, false);
      }
      const meta = document.getElementById('logMeta');
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
      logTimer = setInterval(() => fetchLogs(), Math.max(15, intervalSec) * 1000);
    }

    async function clearLogs() {
      if (!confirm('彻底清除所有RSS日志和推送状态？')) return;
      try {
        await fetch('/api/rss-logs', { method: 'DELETE' });
        await fetchLogs()
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
    setLogVisible(false, false);

    document.getElementById('confirmModal').addEventListener('click', (e) => {
      if (e.target === e.currentTarget) closeConfirmModal();
    });
    document.getElementById('clearAllModal').addEventListener('click', (e) => {
      if (e.target === e.currentTarget) {
        pendingKeywordPin = '';
        closeClearAllModal();
      }
    });
    document.getElementById('pinInput').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        submitKeywords();
      }
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        pendingKeywordPin = '';
        closeConfirmModal();
        closeClearAllModal();
      }
    });
  </script>
  <!-- Web端关键词保存 PIN 验证弹窗 -->
  <div id="confirmModal" class="modal-overlay hidden">
    <div class="modal-box">
      <div class="modal-title">关键词保存验证</div>
      <div class="modal-body" id="confirmMessage">请输入 PIN 码以确认保存关键词修改</div>
      <input id="pinInput" class="pin-input" type="password" inputmode="numeric" maxlength="4" autocomplete="off" aria-label="PIN码" placeholder="••••">
      <div id="pinError" class="modal-error"></div>
      <div class="modal-actions">
        <button class="secondary" type="button" onclick="closeConfirmModal()">取消</button>
        <button type="button" onclick="submitKeywords()">确认保存</button>
      </div>
    </div>
  </div>
  <!-- 两类关键词同时为空时的二次危险确认弹窗 -->
  <div id="clearAllModal" class="modal-overlay hidden">
    <div class="modal-box">
      <div class="modal-title">确认彻底清空？</div>
      <div class="modal-body">当前“关键词”和“静默关键词”都为空。继续后将清空全部关键词；这是高风险操作，需要再次明确确认。</div>
      <div id="clearAllError" class="modal-error"></div>
      <div class="modal-actions">
        <button class="secondary" type="button" onclick="pendingKeywordPin=''; closeClearAllModal()">取消</button>
        <button class="danger" type="button" onclick="confirmClearAllKeywords()">确认彻底清空</button>
      </div>
    </div>
  </div>
</body>
</html>'''
            html_doc = (html_doc
                .replace("__SAFE_KEYWORDS__", safe_keywords)
                .replace("__SAFE_SILENT_KEYWORDS__", safe_silent_keywords)
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
    server.daemon_threads = True
    server.allow_reuse_address = True
    server.timeout = REQUEST_TIMEOUT
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

        web_startup_retries = 0
        max_retries = 3
        while True:
            try:
                cfg = load_runtime_config()
                server = build_keyword_web_server(cfg)
                settings = keyword_web_settings(cfg)
                print(f"node run-all started; monitor interval={max(15, safe_int(cfg.get('INTERVAL_SEC', '15'), 15))}s; keyword web={settings['url']}", flush=True)
                web_startup_retries = 0

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
            except Exception as exc:
                web_startup_retries += 1
                if web_startup_retries >= max_retries:
                    print(f"❌ Web服务启动失败超过{max_retries}次: {exc}", flush=True)
                    return 1
                print(f"⚠️ Web服务启动异常 (重试{web_startup_retries}/{max_retries}): {exc}", flush=True)
                time.sleep(2)
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
