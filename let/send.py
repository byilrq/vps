import requests
import json
import re
import html


class NotificationSender:
    def __init__(self, config):
        self.config = config

    @staticmethod
    def text_to_pushplus_html(message):
        """
        PushPlus 的 txt 模板不会稳定地把 URL 渲染成可点击链接。
        这里将普通文本转换为 HTML：
        - 先整体 escape，避免内容破坏 HTML
        - 再把 http/https URL 转成 <a>
        - 换行转 <br>
        """
        if message is None:
            message = ""

        escaped = html.escape(str(message), quote=True)
        url_re = re.compile(r'(https?://[^\s<>"\'，。；、）\]\}]+)', re.I)

        def repl(match):
            url = match.group(1)
            safe_url = html.escape(url, quote=True)
            return f'<a href="{safe_url}">{safe_url}</a>'

        escaped = url_re.sub(repl, escaped)
        return escaped.replace("\n", "<br>")

    @staticmethod
    def test_telegram_connection(telegram_token, chat_id):
        if not telegram_token or not chat_id:
            return {"ok": False, "message": "Telegram Bot Token 或 Chat ID 为空"}

        url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": "✅ LET Telegram 连通性测试成功"
        }

        try:
            response = requests.post(url, json=payload, timeout=15)
            data = response.json() if response.content else {}

            if response.status_code == 200 and data.get("ok"):
                return {"ok": True, "message": "Telegram 测试消息发送成功"}

            desc = data.get("description") or response.text[:300]
            return {"ok": False, "message": f"Telegram 测试失败：HTTP {response.status_code}，{desc}"}
        except Exception as e:
            return {"ok": False, "message": f"Telegram 请求出错：{e}"}

    @staticmethod
    def test_pushplus_connection(pushplus_token):
        if not pushplus_token:
            return {"ok": False, "message": "PushPlus Token 为空"}

        url = "https://www.pushplus.plus/send"
        test_message = (
            "✅ LET PushPlus 连通性测试成功\n"
            "链接测试：https://www.pushplus.plus/"
        )

        payload = {
            "token": pushplus_token,
            "title": "LET PushPlus 测试",
            "content": NotificationSender.text_to_pushplus_html(test_message),
            "template": "html"
        }

        try:
            response = requests.post(url, json=payload, timeout=15)
            data = response.json() if response.content else {}

            if response.status_code == 200 and str(data.get("code")) == "200":
                return {"ok": True, "message": "PushPlus 测试消息发送成功"}

            msg = data.get("msg") or data.get("message") or response.text[:300]
            return {"ok": False, "message": f"PushPlus 测试失败：HTTP {response.status_code}，{msg}"}
        except Exception as e:
            return {"ok": False, "message": f"PushPlus 请求出错：{e}"}

    def send_telegram_message(self, message):
        telegram_token = self.config.get('telegrambot')
        chat_id = self.config.get('chat_id')

        if not telegram_token or not chat_id:
            print("Telegram 配置缺失：请检查 token 或 chat_id")
            return False

        url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "disable_web_page_preview": False
        }

        try:
            response = requests.post(url, json=payload, timeout=15)
            data = response.json() if response.content else {}

            if response.status_code == 200 and data.get("ok"):
                print("Telegram 消息发送成功")
                return True

            print(f"Telegram 消息发送失败: HTTP {response.status_code} {response.text[:500]}")
            return False
        except Exception as e:
            print(f"发送 Telegram 消息出错: {e}")
            return False

    def send_pushplus_message(self, message):
        pushplus_token = self.config.get('wechat_key') or self.config.get('pushplus_token')

        if not pushplus_token:
            print("PushPlus Token 未配置：请检查 wechat_key / pushplus_token")
            return False

        url = "https://www.pushplus.plus/send"
        payload = {
            "token": pushplus_token,
            "title": "LET 命中通知",
            "content": self.text_to_pushplus_html(message),
            "template": "html"
        }

        try:
            response = requests.post(url, json=payload, timeout=15)
            data = response.json() if response.content else {}

            if response.status_code == 200 and str(data.get("code")) == "200":
                print("PushPlus 消息发送成功")
                return True

            msg = data.get("msg") or data.get("message") or response.text[:500]
            print(f"PushPlus 消息发送失败: HTTP {response.status_code} {msg}")
            return False
        except Exception as e:
            print(f"发送 PushPlus 消息出错: {e}")
            return False

    def send_wechat_message(self, message):
        return self.send_pushplus_message(message)

    def send_custom_message(self, message):
        custom_url = self.config.get('custom_url')

        if not custom_url:
            print("自定义 URL 配置缺失：请检查 custom_url 配置")
            return False

        custom_url_with_message = custom_url.replace("{message}", message)

        try:
            response = requests.get(custom_url_with_message, timeout=15)
            if response.status_code == 200:
                print(f"自定义通知发送成功: {message}")
                return True

            print(f"自定义通知发送失败: {response.status_code} {response.text[:300]}")
            return False
        except Exception as e:
            print(f"发送自定义通知出错: {e}")
            return False



    @staticmethod
    def normalize_ntfy_server(ntfy_server):
        server = str(ntfy_server or "").strip().rstrip("/")
        if not server:
            server = "http://127.0.0.1:8083"
        if not server.startswith(("http://", "https://")):
            server = "http://" + server
        return server

    @staticmethod
    def normalize_ntfy_priority(ntfy_priority):
        try:
            value = int(ntfy_priority)
        except Exception:
            value = 1
        if value < 1 or value > 5:
            value = 1
        return str(value)

    @staticmethod
    def build_ntfy_auth(ntfy_username, ntfy_password):
        username = str(ntfy_username or "").strip()
        password = str(ntfy_password or "")
        if not username:
            return None
        return (username, password)

    @staticmethod
    def test_ntfy_connection(ntfy_server, ntfy_topic, ntfy_username="", ntfy_password="", ntfy_priority=1):
        """测试 ntfy 推送。Header 只使用 ASCII，中文放正文，避免 latin-1 编码错误。"""
        if not ntfy_topic:
            return {"ok": False, "message": "ntfy Topic 为空"}

        server = NotificationSender.normalize_ntfy_server(ntfy_server)
        priority = NotificationSender.normalize_ntfy_priority(ntfy_priority)
        url = f"{server}/{str(ntfy_topic).strip()}"
        headers = {
            "Priority": priority,
        }
        auth = NotificationSender.build_ntfy_auth(ntfy_username, ntfy_password)
        body = "✅ ntfy 连通性测试成功\nhttps://ntfy.sh/"

        try:
            response = requests.post(
                url,
                data=body.encode("utf-8"),
                headers=headers,
                auth=auth,
                timeout=15
            )
            if 200 <= response.status_code < 300:
                return {"ok": True, "message": "ntfy 测试消息发送成功"}

            return {"ok": False, "message": f"ntfy 测试失败：HTTP {response.status_code}，{response.text[:300]}"}
        except Exception as e:
            return {"ok": False, "message": f"ntfy 请求出错：{e}"}

    def send_ntfy_message(self, message):
        """ntfy 推送。支持自建服务地址、Topic、用户名、密码、优先级 1-5。"""
        ntfy_server = self.config.get('ntfy_server', 'http://127.0.0.1:8083')
        ntfy_topic = self.config.get('ntfy_topic')
        ntfy_username = self.config.get('ntfy_username', '')
        ntfy_password = self.config.get('ntfy_password', '')
        ntfy_priority = self.config.get('ntfy_priority', 1)

        if not ntfy_topic:
            print("ntfy Topic 未配置")
            return False

        server = self.normalize_ntfy_server(ntfy_server)
        priority = self.normalize_ntfy_priority(ntfy_priority)
        url = f"{server}/{str(ntfy_topic).strip()}"
        auth = self.build_ntfy_auth(ntfy_username, ntfy_password)

        # Header 必须保持 ASCII，不能放中文，否则 requests 会出现 latin-1 编码错误。
        # 中文标题和正文全部放在 body 里。
        headers = {
            "Priority": priority,
        }
        body = str(message or "")

        try:
            response = requests.post(
                url,
                data=body.encode("utf-8"),
                headers=headers,
                auth=auth,
                timeout=15
            )
            if 200 <= response.status_code < 300:
                print("ntfy 消息发送成功")
                return True

            print(f"ntfy 消息发送失败: HTTP {response.status_code} {response.text[:500]}")
            return False
        except Exception as e:
            print(f"ntfy 请求出错: {e}")
            return False


    @staticmethod
    def test_gotify_connection(gotify_server, gotify_token, gotify_priority=5):
        """测试 Gotify 推送。"""
        if not gotify_server:
            return {"ok": False, "message": "Gotify 服务地址为空"}
        if not gotify_token:
            return {"ok": False, "message": "Gotify Token 为空"}

        server = str(gotify_server or "").strip().rstrip("/")
        if not server.startswith(("http://", "https://")):
            server = "http://" + server

        try:
            priority = int(gotify_priority or 5)
        except Exception:
            priority = 5

        url = f"{server}/message?token={gotify_token}"
        payload = {
            "title": "LET",
            "message": "✅ LET Gotify 连通性测试成功",
            "priority": priority
        }

        try:
            response = requests.post(url, json=payload, timeout=15)
            if 200 <= response.status_code < 300:
                return {"ok": True, "message": "Gotify 测试消息发送成功"}
            return {"ok": False, "message": f"Gotify 测试失败：HTTP {response.status_code}，{response.text[:300]}"}
        except Exception as e:
            return {"ok": False, "message": f"Gotify 请求出错：{e}"}

    def send_gotify_message(self, message):
        """Gotify 推送。"""
        gotify_server = self.config.get('gotify_server')
        gotify_token = self.config.get('gotify_token')
        gotify_priority = self.config.get('gotify_priority', 5)

        if not gotify_server or not gotify_token:
            print("Gotify 配置缺失：请检查 gotify_server / gotify_token")
            return False

        server = str(gotify_server or "").strip().rstrip("/")
        if not server.startswith(("http://", "https://")):
            server = "http://" + server

        try:
            priority = int(gotify_priority or 5)
        except Exception:
            priority = 5

        url = f"{server}/message?token={gotify_token}"
        payload = {
            "title": "LET",
            "message": message,
            "priority": priority
        }

        try:
            response = requests.post(url, json=payload, timeout=15)
            if 200 <= response.status_code < 300:
                print("Gotify 消息发送成功")
                return True
            print(f"Gotify 消息发送失败: HTTP {response.status_code} {response.text[:500]}")
            return False
        except Exception as e:
            print(f"Gotify 请求出错: {e}")
            return False


    def send_message(self, message):
        print(message)
        notice_type = self.config.get('notice_type', 'telegram')

        if notice_type == 'telegram':
            return self.send_telegram_message(message)

        if notice_type in ('wechat', 'pushplus'):
            return self.send_pushplus_message(message)

        if notice_type == 'ntfy':
            return self.send_ntfy_message(message)

        if notice_type == 'gotify':
            return self.send_gotify_message(message)

        if notice_type == 'custom':
            return self.send_custom_message(message)

        print("不支持的通知类型:", notice_type)
        return False


if __name__ == "__main__":
    sender = NotificationSender(config={})
    sender.send_message("测试消息：这是一个通知")
