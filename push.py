#!/usr/bin/env python3
import base64
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from zoneinfo import ZoneInfo
except ImportError:  # Python < 3.9 fallback
    ZoneInfo = None

WORK_DIR = Path(os.environ.get("NODE_WORK_DIR", "/root/node"))
CONFIG_FILE = WORK_DIR / "node_config.txt"

try:
    SHANGHAI_TZ = ZoneInfo("Asia/Shanghai") if ZoneInfo is not None else timezone(timedelta(hours=8), name="Asia/Shanghai")
except Exception:
    # 极简系统若缺少 tzdata，上海当前长期固定为 UTC+8，可安全回退。
    SHANGHAI_TZ = timezone(timedelta(hours=8), name="Asia/Shanghai")


def server_local_now() -> datetime:
    """自动读取系统当前本地时区和时间。"""
    return datetime.now().astimezone()


def shanghai_now() -> datetime:
    return server_local_now().astimezone(SHANGHAI_TZ)


def is_shanghai_quiet_hours(at=None) -> bool:
    """上海时间 [22:30, 次日08:00) 自动降为 ntfy Priority=1。"""
    current = shanghai_now() if at is None else at.astimezone(SHANGHAI_TZ)
    minute_of_day = current.hour * 60 + current.minute
    return minute_of_day >= (22 * 60 + 30) or minute_of_day < 8 * 60


def parse_config(path: Path) -> dict:
    cfg: dict = {}
    if not path.exists():
        return cfg
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
                val = raw_val[1:-1].replace(r'\"', '"').replace(r"\\", "\\")
            else:
                val = raw_val
            cfg[key] = val
    return cfg


def ntfy_send(content: str, priority=None) -> bool:
    cfg = parse_config(CONFIG_FILE)
    url = (cfg.get("NTFY_URL", "http://127.0.0.1:8083") or "http://127.0.0.1:8083").rstrip("/")
    topic = (cfg.get("NTFY_TOPIC", "node") or "node").strip().strip("/")
    username = cfg.get("NTFY_USERNAME", "")
    password = cfg.get("NTFY_PASSWORD", "")
    if priority is None:
        priority = (cfg.get("NTFY_PRIORITY", "3") or "3").strip()
    if priority not in {"1", "2", "3", "4", "5"}:
        priority = "3"
    # 22:30-次日08:00 上海时间统一优先级1，其他时段使用用户设定值。
    if is_shanghai_quiet_hours():
        priority = "1"
    if not url or not topic:
        print("❌ ntfy 配置缺失（NTFY_URL / NTFY_TOPIC）")
        return False
    target = f"{url}/{urllib.parse.quote(topic)}"
    headers = {"Priority": priority, "Content-Type": "text/plain; charset=utf-8"}
    data = content.encode("utf-8")
    req = urllib.request.Request(url=target, data=data, headers=headers, method="POST")
    if username or password:
        token = (f"{username}:{password}").encode("utf-8")
        req.add_header("Authorization", "Basic " + base64.b64encode(token).decode("ascii"))
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.getcode() < 300
    except urllib.error.HTTPError as exc:
        print(f"❌ ntfy 发送失败 HTTP={exc.code} resp={exc.read().decode('utf-8', errors='ignore')[:300]}")
        return False
    except Exception as exc:
        print(f"❌ ntfy 发送异常: {exc}")
        return False


def test_message() -> str:
    cfg = parse_config(CONFIG_FILE)
    now = shanghai_now().strftime("%Y.%m.%d.%H:%M")
    return "\n".join([
        "🎯node",
        f"📆时间: {now}",
        "🔖标题: 这是来自 push.py 的测试推送",
        f"🧬链接: {cfg.get('NS_URL', '') or 'https://rss.nodeseek.com/?sortBy=postTime'}",
    ])


def main(argv: list) -> int:
    if len(argv) < 2:
        print("usage: push.py test|send [priority] <message...>")
        return 1
    cmd = argv[1]
    if cmd == "test":
        ok = ntfy_send(test_message())
    elif cmd == "send":
        priority = None
        content_parts = argv[2:]
        if content_parts and content_parts[0] in {"1", "2", "3", "4", "5"}:
            priority = content_parts[0]
            content_parts = content_parts[1:]
        content = " ".join(content_parts).strip()
        if not content:
            print("❌ 消息内容为空")
            return 1
        ok = ntfy_send(content, priority)
    else:
        print(f"unknown command: {cmd}")
        return 1
    if ok:
        print("✅ 推送已发送")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))