import json
import time
import threading
from bs4 import BeautifulSoup
from datetime import datetime, timezone, timedelta
from send import NotificationSender
import os
import cfscrape
from dotenv import load_dotenv
from urllib.parse import urlparse
from msgparse import thread_message, comment_message
import curl_cffi
from storage_sqlite import SQLiteDB
from filter import Filter
from runtime_log import append_runtime_log
from markdownify import markdownify as md

# Load variables from data/.env
load_dotenv('data/.env')

scraper = cfscrape.create_scraper()


class ForumTask:
    def __init__(self, config_path='data/config.json'):
        self.config_path = config_path
        self._shutdown = False
        self._rss_wakeup = threading.Event()
        self._comment_wakeup = threading.Event()
        self.load_config()

        # 原生轻量版：使用 SQLite 替代 MongoDB，但保留原始策略。
        self.db = SQLiteDB()
        self.threads = self.db['threads']
        self.comments = self.db['comments']

        self.threads.create_index('link', unique=True)
        self.comments.create_index('comment_id', unique=True)

    def current_time(self):
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def record_runtime_log(self, **kwargs):
        try:
            append_runtime_log(kwargs)
        except Exception as e:
            print(f"写入运行日志失败: {e}")

    def manual_runtime_log(self, thread_link, **kwargs):
        """手动链接日志没有特殊路由字段，全部参数传给 append_runtime_log。"""
        kwargs["source"] = "extra_url"
        kwargs["manual_key"] = thread_link
        features = list(kwargs.get("features") or [])
        for item in ["manual_latest", "extra_url"]:
            if item not in features:
                features.insert(0, item)
        kwargs["features"] = features
        self.record_runtime_log(**kwargs)

    def summarize_message(self, text, limit=180):
        text = (text or '').replace('\r', ' ').replace('\n', ' ').strip()
        return text[:limit] + ('...' if len(text) > limit else '')

    def write_config(self):
        """把当前配置写回 data/config.json。

        项目现有 web.py 保存格式为 {"config": ...}，这里沿用同样格式，
        避免自动添加/自动清理手动链接后，重启又恢复旧状态。
        """
        try:
            os.makedirs(os.path.dirname(self.config_path) or '.', exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump({"config": self.config}, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"写入配置文件失败: {e}")

    def _normalize_auto_extra_urls(self):
        auto = self.config.get('auto_extra_urls')
        if isinstance(auto, dict):
            return auto
        if isinstance(auto, list):
            converted = {}
            for item in auto:
                if isinstance(item, dict) and item.get('url'):
                    converted[str(item.get('url')).strip()] = item
            self.config['auto_extra_urls'] = converted
            return converted
        self.config['auto_extra_urls'] = {}
        return self.config['auto_extra_urls']

    def cleanup_auto_extra_urls(self, save=False):
        """删除超过 7 天的"RSS 命中自动加入"的手动帖子链接。

        只删除带有 auto_extra_urls 元数据的链接；用户原本手动填写的链接不会被这里删除。
        """
        auto = self._normalize_auto_extra_urls()
        extra_urls = list(self.config.get('extra_urls') or [])
        now = datetime.now(timezone.utc)
        expired = []

        for url, meta in list(auto.items()):
            expires_at = meta.get('expires_at') if isinstance(meta, dict) else None
            expired_flag = False
            if not expires_at:
                expired_flag = True
            else:
                try:
                    exp = datetime.fromisoformat(str(expires_at).replace('Z', '+00:00'))
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    expired_flag = exp <= now
                except Exception:
                    expired_flag = True
            if expired_flag:
                expired.append(url)

        if not expired:
            return []

        expired_set = set(expired)
        self.config['extra_urls'] = [u for u in extra_urls if u not in expired_set]
        for url in expired:
            auto.pop(url, None)

        if save:
            self.write_config()

        for url in expired:
            self.record_runtime_log(
                type="auto_extra_url",
                source="rss",
                thread_title="自动手动链接过期清理",
                thread_url=url,
                author="",
                role="",
                url=url,
                message_preview="",
                push_message="",
                matched=False,
                reason=f"自动手动链接过期清理",
                features=["auto_extra_url", "expired_7d", "removed"],
            )

        return expired

    def add_auto_extra_url_from_rss_hit(self, thread):
        """RSS 主题命中后，按开关自动加入手动帖子链接。

        注意：这里不会主动扫描楼层。后续是否扫描，仍由 enable_extra_urls
        "手动帖子楼层扫描"总开关决定。
        """
        if not self.config.get('auto_add_rss_hits_to_extra_urls', False):
            return False

        url = (thread.get('link') or '').strip()
        if not url:
            return False

        extra_urls = list(self.config.get('extra_urls') or [])
        auto = self._normalize_auto_extra_urls()

        # 如果用户已经手动写过这个链接，不打自动标记，也不会 7 天后自动删。
        if url in extra_urls and url not in auto:
            return False

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=7)

        added = False
        if url not in extra_urls:
            extra_urls.append(url)
            self.config['extra_urls'] = extra_urls
            added = True

        auto[url] = {
            'url': url,
            'source': 'rss_hit',
            'thread_title': thread.get('title', ''),
            'added_at': now.isoformat(),
            'expires_at': expires_at.isoformat(),
            'ttl_days': 7,
        }
        self.config['auto_extra_urls'] = auto
        self.write_config()

        self.record_runtime_log(
            type="auto_extra_url",
            source="rss",
            thread_title=thread.get('title', ''),
            thread_url=url,
            author=thread.get('creator', ''),
            role="",
            url=url,
            message_preview=self.summarize_message(thread.get('description', '')),
            push_message="",
            matched=True,
            reason=(
                "RSS 命中主题帖已自动加入手动帖子链接，7 天后自动删除；"
                "是否扫描该链接仍受「手动帖子楼层扫描」开关控制"
            ),
            features=["auto_extra_url", "rss_hit", "ttl=7d"] + ([] if added else ["refreshed"]),
        )
        return True

    def load_config(self):
        if not os.path.exists(self.config_path):
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump({"config": {}}, f, indent=4, ensure_ascii=False)
        with open(self.config_path, 'r', encoding='utf-8') as f:
            raw = json.load(f)
        self.config = raw.get('config', raw)

        # 只保留扫描总开关：默认关闭，打开后才扫描/记录/推送。
        self.config.setdefault('enable_rss', False)
        self.config.setdefault('enable_extra_urls', False)
        # RSS 命中主题帖自动加入手动帖子链接：默认关闭。
        # 仅负责"自动加入/过期删除链接"；是否扫描这些链接仍然受 enable_extra_urls 控制。
        self.config.setdefault('auto_add_rss_hits_to_extra_urls', False)
        self.config.setdefault('auto_extra_urls', {})
        self.config.setdefault('rss_scan_limit', 10)
        self.config.setdefault('rss_interval', 300)
        self.config.setdefault('comment_interval', 300)
        self.config.setdefault('comment_filter', 'by_author')
        # 24H 命中推送限制：默认关闭，即不限制评论/主题时间。
        self.config.setdefault('restrict_24h', False)

        # 关键词过滤拆分：
        # 主题关键词只影响 RSS 新主题帖。
        # 楼层关键词只影响手动帖子楼层评论。
        # 兼容旧配置：旧 use_keywords_filter / keywords_rule 默认迁移到楼层关键词。
        self.config.setdefault('use_thread_keywords_filter', False)
        self.config.setdefault('thread_keywords_rule', '')
        self.config.setdefault('use_comment_keywords_filter', self.config.get('use_keywords_filter', False))
        self.config.setdefault('comment_keywords_rule', self.config.get('keywords_rule', ''))

        self.cleanup_auto_extra_urls(save=True)

        self.notifier = NotificationSender(self.config)
        self.filter = Filter(self.config)
        print("配置文件加载成功")

    def shutdown(self):
        """标记停机，主循环退出。"""
        self._shutdown = True
        self._rss_wakeup.set()
        self._comment_wakeup.set()

    def request_immediate_scan(self, rss=False, comments=False):
        """唤醒对应巡检线程，使已开启的扫描立即执行下一轮。"""
        if rss:
            self._rss_wakeup.set()
        if comments:
            self._comment_wakeup.set()

    # -------- RSS LET/LES -----------
    def check_lets(self, urls):
        """
        RSS 只推送最新主题帖，不爬楼层。
        原始版 convert_rss 后还会 fetch_comments(thread_data)，这里按用户要求移除。
        """
        for url in urls:
            try:
                domain = url.split("//")[1].split(".")[0]
                category = url.split("/")[4]
            except Exception:
                parsed = urlparse(url)
                domain = parsed.netloc.split(".")[0]
                category = "unknown"

            print(f"[{self.current_time()}] 检查 {domain} {category} RSS...")
            try:
                res = scraper.get(url)
            except Exception as e:
                print(f"获取 {domain} RSS 出错: {e}")
                continue

            if res.status_code != 200:
                print(f"获取 {domain} 失败")
                continue

            soup = BeautifulSoup(res.text, 'xml')
            try:
                rss_limit = int(self.config.get('rss_scan_limit', 10) or 10)
            except Exception:
                rss_limit = 10
            rss_limit = max(1, min(rss_limit, 30))

            items = soup.find_all('item')[:rss_limit]
            if not items:
                self.record_runtime_log(
                    type="thread",
                    source="rss",
                    thread_title=f"{domain} {category}",
                    thread_url=url,
                    author="",
                    role="",
                    url=url,
                    message_preview="",
                    push_message="",
                    matched=False,
                    reason=f"RSS 前{rss_limit}条检查：未读取到 item",
                    features=[f"RSS前{rss_limit}条", "未读取到内容"],
                )
                continue

            for idx, item in enumerate(items, 1):
                self.convert_rss(item, domain, category, rss_index=idx, rss_limit=rss_limit)

    # -------- EXTRA URLS -----------
    def check_extra_urls(self, urls):
        """
        如果有 thread 且没被重置则爬楼。
        fetch_thread_page 创建新 thread 后立即在同一周期爬楼，不等下一轮。
        """
        for url in urls:
            if getattr(self, '_shutdown', False):
                break
            print(f"[{self.current_time()}] 检查 extra URL: {url}")
            thread = self.threads.find_one({'link': url})
            if thread:
                self.fetch_comments(thread)
            else:
                # 数据库已清空（重置后首次），创建 thread 后立即爬楼
                new_thread = self.fetch_thread_page(url)
                if new_thread:
                    self.fetch_comments(new_thread)

    def parse_rss_date(self, text):
        for fmt in ("%a, %d %b %Y %H:%M:%S +0000", "%a, %d %b %Y %H:%M:%S %z"):
            try:
                return datetime.strptime(text, fmt)
            except Exception:
                pass
        return datetime.now(timezone.utc)

    def convert_rss(self, item, domain, category, rss_index=None, rss_limit=None):
        title_el = item.find('title')
        link_el = item.find('link')
        desc_el = item.find('description')
        creator_el = item.find('dc:creator') or item.find('creator')
        pub_el = item.find('pubDate')

        title = title_el.text if title_el else ""
        link = link_el.text if link_el else ""
        desc = BeautifulSoup(desc_el.text if desc_el else "", 'lxml').text
        creator = creator_el.text if creator_el else ""
        pub_date = self.parse_rss_date(pub_el.text if pub_el else "")

        if not link:
            return

        thread_data = {
            'domain': domain,
            'category': category,
            'title': title,
            'link': link,
            'description': desc,
            'creator': creator,
            'pub_date': pub_date,
            'created_at': datetime.now(timezone.utc),
            'last_page': 1,
            'rss_index': rss_index,
            'rss_limit': rss_limit
        }

        self.handle_thread(thread_data)
        # 注意：按本次要求，RSS 不再 fetch_comments，不爬楼层。

    # -------- 线程存储 + 通知 --------
    def handle_thread(self, thread):
        rss_index = thread.get('rss_index')
        rss_limit = thread.get('rss_limit') or self.config.get('rss_scan_limit', 10)
        rss_trace_prefix = f"RSS 前{rss_limit}条第{rss_index}条：" if rss_index else f"RSS 前{rss_limit}条："

        # RSS 主题唯一键：以 thread['link'] 为准。
        # 同一个主题不管 AI 每次总结是否不同，都只允许推送一次。
        thread_link = (thread.get('link') or '').strip()

        def rss_features(*items):
            features = [f"RSS前{rss_limit}条"]
            if rss_index:
                features.append(f"第{rss_index}条")
            for item in items:
                if item:
                    features.append(str(item))
            return features

        def log_thread(matched, reason, features, push_message=""):
            self.record_runtime_log(
                type="thread",
                source="rss",
                thread_title=thread.get('title', ''),
                thread_url=thread_link,
                author=thread.get('creator', ''),
                role="",
                url=thread_link,
                message_preview=self.summarize_message(thread.get('description', '')),
                push_message=push_message,
                matched=matched,
                reason=reason,
                features=features,
            )

        def save_state(pushed=False, filter_reason="", filter_features=None, push_message=""):
            update = {
                'rss_pushed': bool(pushed),
                'rss_processed': True,
                'rss_filter_reason': filter_reason or "",
                'rss_filter_features': filter_features or [],
                'rss_push_message': push_message or "",
                'rss_checked_at': datetime.now(timezone.utc),
            }
            if pushed:
                update['rss_pushed_at'] = datetime.now(timezone.utc)

            self.threads.update_one(
                {'link': thread_link},
                {'$set': update},
                upsert=False
            )

        exists = self.threads.find_one({'link': thread_link})

        if exists:
            # 兼容旧数据库：老版本没有 rss_pushed 字段，但如果历史命中日志里已经推过，
            # 也视为已推送，避免升级后对同一个主题反复补推。
            already_pushed = bool(exists.get('rss_pushed', False))

            if not already_pushed:
                try:
                    history_hit = self.threads.find_one({
                        'link': thread_link,
                    })
                    already_pushed = bool(history_hit and history_hit.get('rss_pushed', False))
                except Exception:
                    already_pushed = False
        else:
            self.threads.insert_one(thread)
            exists = {}
            already_pushed = False

        # 已推送过的主题，每周期记录一条日志，便于在 RSS 全部中看到状态跟踪。
        if already_pushed:
            reason = f"{rss_trace_prefix}主题帖已存在，已推送"
            features = rss_features("已存在", "已推送")
            save_state(True, reason, features, exists.get('rss_push_message', '') if exists else '')
            log_thread(False, reason, features, exists.get('rss_push_message', '') if exists else '')
            return

        # 已处理过但未命中的主题（24h/关键词/AI 任一未通过），不再重复过滤，直接跳过 AI 调用。
        # 兼容旧库：无 rss_processed 字段时，若已有 filter_features/filter_reason 也视为已处理。
        already_processed = (
            exists
            and not already_pushed
            and (
                exists.get('rss_processed')
                or exists.get('rss_filter_features')
                or exists.get('rss_filter_reason')
            )
        )
        if already_processed:
            reason = f"{rss_trace_prefix}主题帖已存在，已过滤处理，跳过重复过滤"
            features = rss_features("已存在", "已处理跳过")
            save_state(False, reason, features)
            log_thread(False, reason, features)
            return

        age_seconds = (datetime.now(timezone.utc) - thread['pub_date'].replace(tzinfo=timezone.utc)).total_seconds()
        restrict_24h = self.config.get('restrict_24h', False)

        if restrict_24h and age_seconds > 86400:
            reason = f"{rss_trace_prefix}主题帖已存在，未推送，超过 24 小时限制" if exists else f"{rss_trace_prefix}新主题超过 24 小时，未推送"
            features = rss_features("未推送", "超过24小时限制")
            save_state(False, reason, features)
            log_thread(False, reason, features)
            return

        if self.config.get('use_thread_keywords_filter', False) and (
            not self.filter.keywords_filter(
                f"{thread.get('title', '')}\n{thread.get('description', '')}",
                self.config.get('thread_keywords_rule', '')
            )
        ):
            reason = f"{rss_trace_prefix}主题帖已存在，未推送，主题关键词未命中" if exists else f"{rss_trace_prefix}新主题关键词未命中，未推送"
            features = rss_features("未推送", "主题关键词未命中")
            save_state(False, reason, features)
            log_thread(False, reason, features)
            return

        if self.config.get('use_ai_filter', False):
            ai_description = self.filter.ai_filter(thread['description'], self.config['thread_prompt'])
            if 'false' in ai_description.lower():
                reason = f"{rss_trace_prefix}主题帖已存在，未推送，AI 过滤未通过" if exists else f"{rss_trace_prefix}新主题 AI 过滤未通过，未推送"
                features = rss_features("未推送", "AI过滤未通过")
                save_state(False, reason, features)
                log_thread(False, reason, features)
                return
        else:
            ai_description = ""

        msg = thread_message(thread, ai_description)

        # 当前配置下命中，并且没有推送记录，只推送一次。
        self.notifier.send_message(msg)

        reason = f"{rss_trace_prefix}主题帖已存在，已补推" if exists else f"{rss_trace_prefix}新主题命中，已推送"
        features = rss_features("命中", "已推送")
        push_message = ai_description or msg
        save_state(True, reason, features, push_message)
        log_thread(True, reason, features, push_message)
        self.add_auto_extra_url_from_rss_hit(thread)


    def fetch_comments(self, thread):
        db_thread = self.threads.find_one({'link': thread['link']})
        if not db_thread:
            return

        last_page = db_thread.get('last_page', 1)
        if last_page < 1:
            last_page = 1

        start_page = last_page
        pages_checked = []
        total_comments = 0
        new_comments = 0
        pushed_comments = 0
        filtered_comments = 0

        while True:
            if getattr(self, '_shutdown', False):
                print(f"[{self.current_time()}] 检测到停机信号，终止爬楼")
                break

            page_url = f"{thread['link']}/p{last_page}"
            print(f"获取评论页面 {page_url} ...")

            self.manual_runtime_log(
                thread['link'],
                type="comment_check",
                thread_title=thread.get('title', ''),
                thread_url=thread.get('link', ''),
                author="",
                role="",
                url=page_url,
                message_preview="",
                matched=False,
                reason=f"正在爬取第 {last_page} 页楼层...",
                features=["crawling", f"page={last_page}"],
            )

            try:
                res = curl_cffi.get(page_url, impersonate="chrome124", timeout=20)
            except Exception as e:
                print(f"获取评论失败 {page_url}: {e}")
                self.manual_runtime_log(
                    thread['link'],
                    type="comment_check",
                    thread_title=thread.get('title', ''),
                    thread_url=thread.get('link', ''),
                    author="",
                    role="",
                    url=page_url,
                    message_preview="",
                    matched=False,
                    reason=f"手动链接楼层请求失败：p{last_page}，{e}",
                    features=["request_error", f"page={last_page}"],
                )
                break

            if res.status_code != 200:
                if res.status_code == 404:
                    self.threads.update_one(
                        {'link': thread['link']},
                        {'$set': {'last_page': last_page - 1}}
                    )
                    self.manual_runtime_log(
                        thread['link'],
                        type="comment_check",
                        thread_title=thread.get('title', ''),
                        thread_url=thread.get('link', ''),
                        author="",
                        role="",
                        url=thread.get('link', ''),
                        message_preview="",
                        matched=(pushed_comments > 0),
                        reason=(
                            f"手动链接本轮刷楼完成：从 p{start_page} 刷到 p{last_page - 1}，"
                            f"遇到 p{last_page} 404 停止；解析 {total_comments} 条，新入库 {new_comments} 条，"
                            f"推送 {pushed_comments} 条，过滤 {filtered_comments} 条"
                        ),
                        features=[
                            "manual_done",
                            f"start_page={start_page}",
                            f"end_page={last_page - 1}",
                            f"parsed={total_comments}",
                            f"new={new_comments}",
                            f"pushed={pushed_comments}",
                            f"filtered={filtered_comments}",
                        ],
                    )
                    break
                else:
                    print(f"获取评论失败 {page_url} 状态码 {res.status_code}")
                    self.manual_runtime_log(
                        thread['link'],
                        type="comment_check",
                        thread_title=thread.get('title', ''),
                        thread_url=thread.get('link', ''),
                        author="",
                        role="",
                        url=page_url,
                        message_preview="",
                        matched=False,
                        reason=f"手动链接楼层请求失败：HTTP {res.status_code}",
                        features=["http_error", f"page={last_page}"],
                    )
                    break

            pages_checked.append(last_page)
            result = self.parse_comments(res.text, thread)
            total_comments += result["total"]
            new_comments += result["new"]
            pushed_comments += result["pushed"]
            filtered_comments += result["filtered"]

            last_page += 1
            time.sleep(1)

    # -------- 通用评论解析 --------
    def parse_comments(self, html, thread):
        soup = BeautifulSoup(html, 'html.parser')
        items = soup.find_all('li', class_='ItemComment')

        stats = {"total": 0, "new": 0, "pushed": 0, "filtered": 0}

        for it in items:
            cid = it.get('id')
            if not cid:
                continue
            cid = cid.split('_')[1] if '_' in cid else cid.replace("Comment_", "")

            author_el = it.find('a', class_='Username')
            if not author_el:
                continue
            author = author_el.text

            role = it.find('span', class_='RoleTitle').text if it.find('span', class_='RoleTitle') else None

            message_div = it.find('div', class_='Message')
            if message_div:
                msg_parts = []
                for element in message_div.children:
                    if element.name == 'blockquote' and 'UserQuote' in element.get('class', []):
                        pass
                    else:
                        text = md(str(element)).strip()
                        if text:
                            msg_parts.append(text)
                msg = '\n'.join(msg_parts)
            else:
                msg = ""

            time_el = it.find('time')
            if not time_el or not time_el.has_attr('datetime'):
                continue
            created = time_el['datetime']

            stats["total"] += 1

            # 保持原始过滤策略：在解析阶段先过滤角色/作者。
            if self.config.get('comment_filter') == 'by_role':
                if not role or role.strip().lower() == 'member':
                    stats["filtered"] += 1
                    continue

            if self.config.get('comment_filter') == 'by_author':
                if author != thread['creator']:
                    stats["filtered"] += 1
                    continue

            comment = {
                'comment_id': f"{thread['domain']}_{cid}",
                'thread_url': thread['link'],
                'author': author,
                'message': msg,
                'created_at': datetime.strptime(created, "%Y-%m-%dT%H:%M:%S+00:00"),
                'created_at_recorded': datetime.now(timezone.utc),
                'url': f"https://{thread['domain']}.com/discussion/comment/{cid}/#Comment_{cid}"
            }

            result = self.handle_comment(comment, thread)
            if result == "duplicate":
                continue
            stats["new"] += 1
            if result == "pushed":
                stats["pushed"] += 1
            else:
                stats["filtered"] += 1

        return stats

    # -------- 存储评论 + 通知 --------
    def handle_comment(self, comment, thread):
        if self.comments.find_one({'comment_id': comment['comment_id']}):
            return "duplicate"

        self.comments.update_one({'comment_id': comment['comment_id']},
                                 {'$set': comment}, upsert=True)

        age_seconds = (datetime.now(timezone.utc) - comment['created_at'].replace(tzinfo=timezone.utc)).total_seconds()
        restrict_24h = self.config.get('restrict_24h', False)

        if restrict_24h and age_seconds > 86400:
            self.manual_runtime_log(
                thread['link'],
                type="comment",
                thread_title=thread.get('title', ''),
                thread_url=thread.get('link', ''),
                comment_id=comment.get('comment_id', ''),
                author=comment.get('author', ''),
                role="",
                url=comment.get('url', ''),
                message_preview=self.summarize_message(comment.get('message', '')),
                matched=False,
                reason="评论超过 24 小时，因 24H 限制未推送",
                features=["older_than_24h", "restrict_24h=true"],
            )
            return "filtered"

        if self.config.get('use_comment_keywords_filter', self.config.get('use_keywords_filter', False)) and (
            not self.filter.keywords_filter(comment['message'], self.config.get('comment_keywords_rule', self.config.get('keywords_rule', '')))
        ):
            self.manual_runtime_log(
                thread['link'],
                type="comment",
                thread_title=thread.get('title', ''),
                thread_url=thread.get('link', ''),
                comment_id=comment.get('comment_id', ''),
                author=comment.get('author', ''),
                role="",
                url=comment.get('url', ''),
                message_preview=self.summarize_message(comment.get('message', '')),
                matched=False,
                reason="楼层关键词过滤未命中",
                features=["comment_keywords_filter", f"rule={self.config.get('comment_keywords_rule', self.config.get('keywords_rule', ''))}"],
            )
            return "filtered"

        if self.config.get('use_ai_filter', False):
            ai_description = self.filter.ai_filter(comment['message'], self.config['comment_prompt'])
            if 'false' in ai_description.lower():
                self.manual_runtime_log(
                    thread['link'],
                    type="comment",
                    thread_title=thread.get('title', ''),
                    thread_url=thread.get('link', ''),
                    comment_id=comment.get('comment_id', ''),
                    author=comment.get('author', ''),
                    role="",
                    url=comment.get('url', ''),
                    message_preview=self.summarize_message(comment.get('message', '')),
                    matched=False,
                    reason="AI 过滤未命中",
                    features=["ai_filter=false"],
                )
                return "filtered"
        else:
            ai_description = ""

        msg = comment_message(thread, comment, ai_description)
        self.manual_runtime_log(
            thread['link'],
            type="comment",
            thread_title=thread.get('title', ''),
            thread_url=thread.get('link', ''),
            comment_id=comment.get('comment_id', ''),
            author=comment.get('author', ''),
            role="",
            url=comment.get('url', ''),
            message_preview=self.summarize_message(comment.get('message', '')),
            push_message=ai_description or msg,
            matched=True,
            reason="手动链接新评论命中，已按原始格式推送",
            features=["new_comment"] + (["restrict_24h=false"] if not restrict_24h else ["within_24h"]),
        )
        self.notifier.send_message(msg)
        return "pushed"

    # -------- 主循环 --------
    def start_tasking(self):
        print("开始监控...")

        while True:
            try:
                if getattr(self, '_shutdown', False):
                    print(f"[{self.current_time()}] 检测到停机信号，线程退出")
                    return

                self.load_config()
                freq = self.config.get('comment_interval', 300)

                if self.config.get('enable_extra_urls', False):
                    self.check_extra_urls(urls=self.config.get('extra_urls', []))
                else:
                    print(f"[{self.current_time()}] 手动链接扫描关闭：不扫描、不记录、不推送")

                print(f"[{self.current_time()}] 手动爬楼结束，休眠 {freq} 秒...")
                self._comment_wakeup.wait(timeout=freq)
                self._comment_wakeup.clear()
                if getattr(self, '_shutdown', False):
                    print(f"[{self.current_time()}] 检测到停机信号，线程退出")
                    return
            except Exception as e:
                print(f"发生错误: {e}")
                self._comment_wakeup.wait(timeout=60)
                self._comment_wakeup.clear()

    def _rss_loop(self):
        """独立 RSS 巡检线程，不受爬楼阻塞。"""
        while True:
            try:
                if getattr(self, '_shutdown', False):
                    return

                self.load_config()
                freq = self.config.get('rss_interval', 300)

                if self.config.get('enable_rss', False):
                    self.check_lets(urls=self.config.get('urls', [
                        "https://lowendspirit.com/categories/offers/feed.rss",
                        "https://lowendtalk.com/categories/offers/feed.rss"
                    ]))
                else:
                    print(f"[{self.current_time()}] RSS 扫描关闭：不扫描、不记录、不推送")

                print(f"[{self.current_time()}] RSS 巡检结束，休眠 {freq} 秒...")
                self._rss_wakeup.wait(timeout=freq)
                self._rss_wakeup.clear()
                if getattr(self, '_shutdown', False):
                    return
            except Exception as e:
                print(f"RSS 巡检异常: {e}")
                self._rss_wakeup.wait(timeout=60)
                self._rss_wakeup.clear()

    def reload(self):
        print("重新加载配置...")
        self.load_config()


if __name__ == "__main__":
    task = ForumTask()
    task.start_tasking()

# ---- hotfix: restore missing fetch_thread_page after patch merge ----
def _let_hotfix_fetch_thread_page(self, url):
    """
    清库后首次遇到手动帖子链接时，建立 thread 状态。
    自动从页面解析楼主，确保 by_author 过滤能正常工作。
    后续 check_extra_urls 会通过 fetch_comments(thread) 爬楼。
    """
    try:
        from urllib.parse import urlparse
        from datetime import datetime, timezone
        import curl_cffi
        from bs4 import BeautifulSoup

        thread_link = (url or "").strip().rstrip("/")
        if not thread_link:
            return None

        exists = self.threads.find_one({"link": thread_link})
        if exists:
            return exists

        parsed = urlparse(thread_link)
        domain = parsed.netloc.split(".")[0] if parsed.netloc else "unknown"

        # 自动从页面提取楼主（首帖作者），首帖在 div.ItemDiscussion 中，不在 li.ItemComment 里
        creator = ""
        try:
            res = curl_cffi.get(thread_link + "/p1", impersonate="chrome124", timeout=15)
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, 'html.parser')
                op_section = soup.find('div', class_='ItemDiscussion')
                if op_section:
                    author_el = op_section.find('a', class_='Username')
                    if author_el:
                        creator = author_el.text.strip()
        except Exception:
            pass

        thread = {
            "domain": domain,
            "category": "extra",
            "title": thread_link.rsplit("/", 1)[-1] or thread_link,
            "link": thread_link,
            "description": "",
            "creator": creator,
            "pub_date": datetime.now(timezone.utc),
            "created_at": datetime.now(timezone.utc),
            "last_page": 1,
            "source": "extra_url"
        }

        self.threads.insert_one(thread)

        try:
            self.manual_runtime_log(
                thread_link,
                type="comment_check",
                thread_title=thread.get("title", ""),
                thread_url=thread_link,
                author=creator,
                role="",
                url=thread_link,
                message_preview="",
                matched=False,
                reason=f"手动链接首次加入，楼主：{creator}，已建立状态；下轮开始爬楼",
                features=["manual_init", "extra_url"],
            )
        except Exception:
            pass

        return thread
    except Exception as e:
        print(f"fetch_thread_page hotfix error: {e}")
        return None


if not hasattr(ForumTask, "fetch_thread_page"):
    ForumTask.fetch_thread_page = _let_hotfix_fetch_thread_page
# ---- end hotfix ----
