#!/usr/bin/env python3
import base64
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

WORK_DIR = Path("/root/node")
CONFIG_FILE = WORK_DIR / "node_config.txt"


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
    now = datetime.now().strftime("%Y.%m.%d.%H:%M")
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