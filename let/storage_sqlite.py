# -*- coding: utf-8 -*-
"""轻量 SQLite 存储层，用于替代 MongoDB。
只实现本项目实际用到的少量 collection 方法：find_one / insert_one / update_one / create_index。
"""

import json
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, Optional

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.environ.get("LET_SQLITE", os.path.join(DATA_DIR, "let.sqlite3"))

os.makedirs(DATA_DIR, exist_ok=True)


def _json_default(obj: Any) -> str:
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def _json_loads(raw: str) -> Dict[str, Any]:
    data = json.loads(raw)
    # 尽量恢复本项目里会参与时间计算的字段。
    for key in ("pub_date", "created_at", "created_at_recorded"):
        val = data.get(key)
        if isinstance(val, str):
            try:
                data[key] = datetime.fromisoformat(val)
            except Exception:
                pass
    return data


class SQLiteCollection:
    def __init__(self, name: str, key_field: str):
        self.name = name
        self.key_field = key_field
        self.table = f"items_{name}"
        self._init_table()

    def clear(self) -> None:
        """清空该 collection 的所有数据。"""
        with self._connect() as conn:
            conn.execute(f"DELETE FROM {self.table}")
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_table(self) -> None:
        with self._connect() as conn:
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self.table} (
                    k TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()

    def create_index(self, *args, **kwargs) -> None:
        return None

    def _key_from_doc(self, doc: Dict[str, Any]) -> Optional[str]:
        value = doc.get(self.key_field)
        return None if value is None else str(value)

    def _key_from_query(self, query: Dict[str, Any]) -> Optional[str]:
        value = query.get(self.key_field)
        return None if value is None else str(value)

    def find_one(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        key = self._key_from_query(query)
        if key is None:
            return None
        with self._connect() as conn:
            row = conn.execute(f"SELECT payload FROM {self.table} WHERE k = ?", (key,)).fetchone()
        if not row:
            return None
        return _json_loads(row["payload"])

    def insert_one(self, doc: Dict[str, Any]):
        key = self._key_from_doc(doc)
        if key is None:
            raise ValueError(f"document missing key field: {self.key_field}")
        payload = json.dumps(doc, ensure_ascii=False, default=_json_default)
        with self._connect() as conn:
            conn.execute(
                f"INSERT OR IGNORE INTO {self.table}(k, payload) VALUES (?, ?)",
                (key, payload),
            )
            conn.commit()
        return {"inserted_id": key}

    def update_one(self, query: Dict[str, Any], update: Dict[str, Any], upsert: bool = False):
        key = self._key_from_query(query)
        if key is None:
            return {"matched_count": 0, "modified_count": 0}

        current = self.find_one(query)
        if current is None:
            if not upsert:
                return {"matched_count": 0, "modified_count": 0}
            current = dict(query)

        if "$set" in update:
            current.update(update["$set"])
        else:
            current.update(update)

        # 确保主键字段存在。
        current[self.key_field] = current.get(self.key_field, key)
        payload = json.dumps(current, ensure_ascii=False, default=_json_default)
        with self._connect() as conn:
            conn.execute(
                f"REPLACE INTO {self.table}(k, payload, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                (key, payload),
            )
            conn.commit()
        return {"matched_count": 1, "modified_count": 1}


class SQLiteDB:
    def __init__(self):
        self.threads = SQLiteCollection("threads", "link")
        self.comments = SQLiteCollection("comments", "comment_id")

    def clear_all(self) -> None:
        """清空所有 collection，重新开始。"""
        self.threads.clear()
        self.comments.clear()

    def __getitem__(self, name: str) -> SQLiteCollection:
        if name == "threads":
            return self.threads
        if name == "comments":
            return self.comments
        return SQLiteCollection(name, "id")
