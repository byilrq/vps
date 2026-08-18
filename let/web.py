from flask import Flask, request, jsonify, render_template
from core import ForumTask
from send import NotificationSender
from filter import Filter, get_ai_stats
from runtime_log import (
    read_rss_all, read_rss_hits,
    read_comment_all, read_comment_hits,
    clear_runtime_logs,
)
import json
import threading
from dotenv import load_dotenv
import os
from datetime import datetime
from functools import wraps

load_dotenv('data/.env')
expected_token = os.getenv('ACCESS_TOKEN', 'default_token')

app = Flask(__name__)
_engine_lock = threading.Lock()
engine = ForumTask()
engine_thread = threading.Thread(target=engine.start_tasking, daemon=True)
rss_thread = threading.Thread(target=engine._rss_loop, daemon=True)

# 避免冲突
app.jinja_env.variable_start_string = '<<'
app.jinja_env.variable_end_string = '>>'


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or token != f"Bearer {expected_token}":
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function


def get_request_config():
    data = request.get_json(silent=True) or {}
    if isinstance(data, dict) and isinstance(data.get('config'), dict):
        return data['config']
    if isinstance(data, dict) and data:
        return data
    return engine.config



def _norm_url(value):
    """用于比较链接是否相同：忽略首尾空白和末尾 /。"""
    return str(value or "").strip().rstrip("/")


def _load_saved_config():
    """读取当前磁盘配置，用于判断自动链接是否被用户删除/重新手动加入。"""
    path = getattr(engine, "config_path", "data/config.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict):
            return raw.get("config", raw)
    except Exception:
        pass
    return dict(getattr(engine, "config", {}) or {})


def _normalize_auto_extra_map(auto_extra):
    """兼容 dict / list 两种 auto_extra_urls 存储格式，返回 norm_url -> (original_key, meta)。"""
    result = {}
    if isinstance(auto_extra, dict):
        for key, meta in auto_extra.items():
            raw_url = key
            if isinstance(meta, dict) and meta.get("url"):
                raw_url = meta.get("url")
            norm = _norm_url(raw_url)
            if norm:
                result[norm] = (key, meta)
    elif isinstance(auto_extra, list):
        for item in auto_extra:
            if isinstance(item, dict):
                raw_url = item.get("url")
                norm = _norm_url(raw_url)
                if norm:
                    result[norm] = (raw_url, item)
            else:
                norm = _norm_url(item)
                if norm:
                    result[norm] = (item, {"url": str(item)})
    return result


def _protect_auto_extra_urls_on_save(config_data):
    """
    保存配置时保护自动加入的 RSS 命中主题帖：
    1. 用户从手动帖子输入框删掉某个自动链接并保存 -> 同步从 auto_extra_urls 移除，避免下次又恢复。
    2. 用户先删除自动链接保存，之后又手动加回同链接保存 -> 视为手动维护，不再自动过期。
    3. 普通保存不会把仍在自动周期内的链接误升级为手动项，7 天自动清理仍然有效。
    """
    if not isinstance(config_data, dict):
        return config_data

    old_config = _load_saved_config()
    old_auto_map = _normalize_auto_extra_map(old_config.get("auto_extra_urls"))
    if not old_auto_map:
        return config_data

    new_extra_urls = config_data.get("extra_urls") or []
    if not isinstance(new_extra_urls, list):
        new_extra_urls = []
    new_extra_norm = {_norm_url(u) for u in new_extra_urls if _norm_url(u)}

    old_extra_urls = old_config.get("extra_urls") or []
    if not isinstance(old_extra_urls, list):
        old_extra_urls = []
    old_extra_norm = {_norm_url(u) for u in old_extra_urls if _norm_url(u)}

    # 仍在自动列表，且这次保存后仍保留在 extra_urls 里的，才继续保留自动元数据。
    # 如果用户删除了该链接，或之前删除后又重新加回，都移除自动元数据。
    kept = {}
    for norm, (original_key, meta) in old_auto_map.items():
        if norm not in new_extra_norm:
            continue
        if norm not in old_extra_norm:
            # 之前不在 extra_urls，这次新增：视为用户手动加入，不再自动过期。
            continue
        kept[original_key] = meta

    config_data["auto_extra_urls"] = kept
    return config_data


def runtime_server_time():
    return datetime.now().strftime("%Y年%m月%d日 %H:%M:%S")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/config', methods=['GET', 'POST'])
@require_auth
def config():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        config_data = data.get('config', data)
        config_data = _protect_auto_extra_urls_on_save(config_data)
        config_path = getattr(engine, "config_path", "data/config.json")
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump({"config": config_data}, f, indent=4, ensure_ascii=False)
        engine.reload()
        engine.request_immediate_scan(
            rss=bool(config_data.get('enable_rss', False)),
            comments=bool(config_data.get('enable_extra_urls', False)),
        )
        return jsonify({"status": "success", "message": "配置已保存并重新加载"})
    return jsonify(engine.config)


@app.route('/api/scan-now', methods=['POST'])
@require_auth
def scan_now():
    """手动执行一次当前已开启的扫描，不修改配置。"""
    engine.reload()
    rss_enabled = bool(engine.config.get('enable_rss', False))
    extra_enabled = bool(engine.config.get('enable_extra_urls', False))
    engine.request_immediate_scan(rss=rss_enabled, comments=extra_enabled)

    triggered = []
    if rss_enabled:
        triggered.append("RSS 新主题帖")
    if extra_enabled:
        triggered.append("手动帖子楼层")

    if triggered:
        message = "已手动触发一次扫描：" + "、".join(triggered)
    else:
        message = "RSS 和手动帖子楼层扫描均未开启，本次未执行扫描"
    return jsonify({"status": "success", "message": message, "triggered": triggered})


@app.route('/api/runtime-logs', methods=['GET', 'DELETE'])
@require_auth
def runtime_logs():
    """四独立视图日志接口。

    参数 view 指定视图：
      - rss_all      RSS 全部
      - rss_hits     RSS 命中
      - comment_all  楼层全部
      - comment_hits 楼层命中

    DELETE 清空全部四个文件 + 数据库重置。
    """
    if request.method == 'DELETE':
        global engine, engine_thread, rss_thread
        clear_runtime_logs()
        engine.db.clear_all()

        with _engine_lock:
            engine.shutdown()
            engine = ForumTask()
            engine_thread = threading.Thread(target=engine.start_tasking, daemon=True)
            engine_thread.start()
            rss_thread = threading.Thread(target=engine._rss_loop, daemon=True)
            rss_thread.start()
        return jsonify({"status": "success", "message": "已重置，正在从第一页重新爬楼", "logs": [], "server_time": runtime_server_time()})

    view = request.args.get("view", "rss_all")

    reader_map = {
        "rss_all": read_rss_all,
        "rss_hits": read_rss_hits,
        "comment_all": read_comment_all,
        "comment_hits": read_comment_hits,
    }

    reader = reader_map.get(view, read_rss_all)
    logs = reader()

    if view == "rss_all":
        # RSS 全部按 RSS 索引正序：第 1 条排最上面，第 20 条排最下面
        pass
    else:
        # RSS 命中、楼层全部、楼层命中：最新在上面
        logs.reverse()

    return jsonify({
        "status": "success",
        "logs": logs,
        "server_time": runtime_server_time(),
        "ai_stats": get_ai_stats(),
    })


@app.route('/api/test/telegram', methods=['POST'])
@require_auth
def test_telegram():
    cfg = get_request_config()
    result = NotificationSender.test_telegram_connection(cfg.get('telegrambot'), cfg.get('chat_id'))
    status = "success" if result.get('ok') else "error"
    return jsonify({"status": status, **result})


@app.route('/api/test/pushplus', methods=['POST'])
@require_auth
def test_pushplus():
    cfg = get_request_config()
    result = NotificationSender.test_pushplus_connection(cfg.get('wechat_key') or cfg.get('pushplus_token'))
    status = "success" if result.get('ok') else "error"
    return jsonify({"status": status, **result})









@app.route('/api/test/gotify', methods=['POST'])
@require_auth
def test_gotify():
    cfg = get_request_config()
    result = NotificationSender.test_gotify_connection(
        cfg.get('gotify_server'),
        cfg.get('gotify_token'),
        cfg.get('gotify_priority', 5)
    )
    status = "success" if result.get('ok') else "error"
    return jsonify({"status": status, **result})


@app.route('/api/test/ntfy', methods=['POST'])
@require_auth
def test_ntfy():
    cfg = get_request_config()
    result = NotificationSender.test_ntfy_connection(
        cfg.get('ntfy_server', 'http://127.0.0.1:8083'),
        cfg.get('ntfy_topic'),
        cfg.get('ntfy_username', ''),
        cfg.get('ntfy_password', ''),
        cfg.get('ntfy_priority', 1)
    )
    status = "success" if result.get('ok') else "error"
    return jsonify({"status": status, **result})


@app.route('/api/test/workers-ai', methods=['POST'])
@require_auth
def test_workers_ai():
    cfg = get_request_config()
    result = Filter(cfg).test_workers_ai()
    status = "success" if result.get('ok') else "error"
    return jsonify({"status": status, **result})


if __name__ == '__main__':
    engine_thread.start()
    rss_thread.start()
    ssl_cert = os.getenv('SSL_CERT')
    ssl_key = os.getenv('SSL_KEY')
    ssl_context = (ssl_cert, ssl_key) if ssl_cert and ssl_key and os.path.isfile(ssl_cert) and os.path.isfile(ssl_key) else None
    app.run(host=os.getenv('HOST', '0.0.0.0'), port=int(os.getenv('PORT', '8069')), ssl_context=ssl_context)
