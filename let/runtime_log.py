# -*- coding: utf-8 -*-
"""运行日志模块 -- 四独立视图版。

四个独立数据源，各自滚动保存最近 50 条，互不干扰：
  1. rss_all.json       RSS 全部（RSS 相关所有日志）
  2. rss_hits.json      RSS 命中（仅 RSS matched=true）
  3. comment_all.json   楼层全部（手动帖子相关所有日志）
  4. comment_hits.json  楼层命中（仅楼层 matched=true）

不再有全局混用、不再有置顶逻辑。
写入时按来源路由到对应文件，读取时各文件独立返回。
"""

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

MAX_PER_FILE = 50
MAX_PER_HITS = 50
MAX_DISPLAY_ALL = 20
MAX_DISPLAY_HITS = 20

_LOCK = threading.Lock()

# 四文件路径
RSS_ALL_PATH = os.environ.get("LET_RSS_ALL_LOG", os.path.join(DATA_DIR, "rss_all.json"))
RSS_HITS_PATH = os.environ.get("LET_RSS_HIT_LOG", os.path.join(DATA_DIR, "rss_hits.json"))
COMMENT_ALL_PATH = os.environ.get("LET_COMMENT_ALL_LOG", os.path.join(DATA_DIR, "comment_all.json"))
COMMENT_HITS_PATH = os.environ.get("LET_COMMENT_HIT_LOG", os.path.join(DATA_DIR, "comment_hits.json"))

_FILE_CONFIG = {
    "rss_all": {"path": RSS_ALL_PATH, "max": MAX_PER_FILE},
    "rss_hits": {"path": RSS_HITS_PATH, "max": MAX_PER_HITS},
    "comment_all": {"path": COMMENT_ALL_PATH, "max": MAX_PER_FILE},
    "comment_hits": {"path": COMMENT_HITS_PATH, "max": MAX_PER_HITS},
}


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ensure_data_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def _read_json_list(path: str, limit: int | None = None) -> List[Dict[str, Any]]:
    _ensure_data_dir()
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data[-limit:] if limit else data
    except Exception:
        return []
    return []


def _write_json_list(path: str, data: List[Dict[str, Any]]) -> None:
    _ensure_data_dir()
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, path)


# -- 公开读取接口 --

def read_rss_all() -> List[Dict[str, Any]]:
    return _read_json_list(RSS_ALL_PATH, MAX_PER_FILE)[-MAX_DISPLAY_ALL:]

def read_rss_hits() -> List[Dict[str, Any]]:
    return _read_json_list(RSS_HITS_PATH, MAX_PER_HITS)[-MAX_DISPLAY_HITS:]

def read_comment_all() -> List[Dict[str, Any]]:
    return _read_json_list(COMMENT_ALL_PATH, MAX_PER_FILE)[-MAX_DISPLAY_ALL:]

def read_comment_hits() -> List[Dict[str, Any]]:
    return _read_json_list(COMMENT_HITS_PATH, MAX_PER_HITS)[-MAX_DISPLAY_HITS:]


# -- 路由判断 --

def _is_rss_entry(entry: Dict[str, Any]) -> bool:
    """判断一条日志是否属于 RSS 范畴。"""
    features = entry.get("features") or []
    text = " ".join([
        str(entry.get("source", "")),
        str(entry.get("type", "")),
        str(entry.get("reason", "")),
        str(entry.get("thread_title", "")),
        *[str(f) for f in features],
    ])
    return (
        entry.get("source") == "rss"
        or (entry.get("type") == "thread" and ("rss" in text.lower() or "RSS前" in text or "RSS 前" in text))
    )


def _is_comment_entry(entry: Dict[str, Any]) -> bool:
    """判断一条日志是否属于楼层（手动帖子）范畴。"""
    features = entry.get("features") or []
    text = " ".join([
        str(entry.get("type", "")),
        str(entry.get("source", "")),
        str(entry.get("reason", "")),
        str(entry.get("manual_key", "")),
        *[str(f) for f in features],
    ])
    return (
        entry.get("type") in ("comment", "comment_check")
        or bool(entry.get("comment_id"))
        or entry.get("source") == "extra_url"
        or bool(entry.get("manual_key"))
        or any(kw in text.lower() for kw in ["manual", "手动链接", "爬楼", "刷楼", "楼层", "评论", "comment", "extra_url"])
    )


def _append_to_file(path: str, entry: Dict[str, Any], max_count: int, dedupe_key: str | None = None) -> None:
    """向指定文件追加一条记录，滚动保留最近 max_count 条。

    如果 dedupe_key 非 None，按该字段去重（对 hits 文件用）。
    """
    data = _read_json_list(path, max_count)

    if dedupe_key:
        # 去重：移除已存在的相同 key 的记录
        key_val = entry.get(dedupe_key)
        if key_val:
            data = [item for item in data if item.get(dedupe_key) != key_val]

    data.append(entry)
    data = data[-max_count:]
    _write_json_list(path, data)


# -- 写入入口 --

def append_runtime_log(entry: Dict[str, Any]) -> None:
    """主写入入口：按来源路由到四个独立文件。"""
    _ensure_data_dir()

    safe_entry = dict(entry or {})
    safe_entry.setdefault("checked_at", _now())
    safe_entry.setdefault("matched", False)
    safe_entry.setdefault("features", [])
    safe_entry.setdefault("reason", "")

    is_rss = _is_rss_entry(safe_entry)
    is_comment = _is_comment_entry(safe_entry)
    matched = bool(safe_entry.get("matched"))

    with _LOCK:
        # RSS 全部：所有 RSS 相关日志
        if is_rss:
            _append_to_file(RSS_ALL_PATH, safe_entry, MAX_PER_FILE)
        # RSS 命中：仅 RSS 匹配的，按 thread_url 去重
        if is_rss and matched:
            _append_to_file(RSS_HITS_PATH, safe_entry, MAX_PER_HITS, dedupe_key="thread_url")

        # 楼层全部：所有楼层相关日志
        if is_comment:
            _append_to_file(COMMENT_ALL_PATH, safe_entry, MAX_PER_FILE)
        # 楼层命中：仅楼层匹配的，按 comment_id 去重
        if is_comment and matched:
            _append_to_file(COMMENT_HITS_PATH, safe_entry, MAX_PER_HITS, dedupe_key="comment_id")


def clear_runtime_logs() -> None:
    """清空全部四个日志文件。"""
    _ensure_data_dir()
    with _LOCK:
        for cfg in _FILE_CONFIG.values():
            _write_json_list(cfg["path"], [])
