import json
import requests
import os
import shutil
import time
import logging
import threading
import re
from datetime import datetime

# ---------- 配置日志 ----------
LOG_DIR = "logs"  # 日志文件夹
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, f"ai_filter_{datetime.now().strftime('%Y%m%d')}.log")

# ---------- AI 调用统计（按天） ----------
_AI_STATS_FILE = os.path.join(LOG_DIR, "ai_stats.json")
_ai_stats_lock = threading.Lock()
_ai_stats = {"date": "", "calls": 0, "failures": 0}

# 指定用户名的评论只翻译，不做折扣/优惠检测，也不使用 comment_prompt 中的 FALSE / END 协议。
DEFAULT_USER_TRANSLATION_PROMPT = (
    "你是一名精通 VPS、服务器和网络术语的翻译助手。请把以下论坛评论忠实翻译成简体中文。"
    "原文已有中文时保持原意，不必改写。保留原文的链接、价格、货币、优惠码、"
    "配置参数、命令、代码及必要的排版；不要总结、删减、推测或添加原文没有的信息。"
    "不要判断是否属于优惠信息，不要输出 FALSE、END、解释或分析过程，只输出汉化正文。"
)


def _today_str():
    return datetime.now().strftime("%Y-%m-%d")


def _load_ai_stats():
    global _ai_stats
    today = _today_str()
    try:
        with open(_AI_STATS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and data.get("date") == today:
            _ai_stats = data
        else:
            _ai_stats = {"date": today, "calls": 0, "failures": 0}
    except Exception:
        _ai_stats = {"date": today, "calls": 0, "failures": 0}


def _record_ai_call(success):
    global _ai_stats
    with _ai_stats_lock:
        today = _today_str()
        if _ai_stats.get("date") != today:
            _ai_stats = {"date": today, "calls": 0, "failures": 0}
        _ai_stats["calls"] += 1
        if not success:
            _ai_stats["failures"] += 1
        try:
            with open(_AI_STATS_FILE, "w", encoding="utf-8") as f:
                json.dump(_ai_stats, f, ensure_ascii=False)
        except Exception:
            pass


def get_ai_stats():
    _load_ai_stats()
    with _ai_stats_lock:
        return dict(_ai_stats)

# 创建 logger
logger = logging.getLogger("AI_Filter")
logger.setLevel(logging.DEBUG)

# 控制台 Handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# 文件 Handler
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
file_handler.setFormatter(file_formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)
# -------------------------------

class AIOnlyBooleanResponse(RuntimeError):
    """AI API succeeded but only returned a positive boolean, not a usable summary."""


class Filter:
    def __init__(self, config):
        self.config = config
        logger.info("Filter 初始化完成")

    def keywords_filter(self, text, keywords_rule):
        if not keywords_rule.strip():
            return False
        or_groups = [group.strip() for group in keywords_rule.replace(',', ' ').split() if group.strip()]
        for group in or_groups:
            and_keywords = [kw.strip() for kw in group.split('&') if kw.strip()]
            if and_keywords and all(kw.lower() in text.lower() for kw in and_keywords):
                return True
        return False

    # -------- AI 相关功能 --------
    def workers_ai_run(self, model, inputs):
        """调用 Cloudflare Workers AI，并记录详细请求/响应日志"""
        headers = {
            "Authorization": f"Bearer {self.config['cf_token']}",
            "Content-Type": "application/json"
        }
        payload = {"messages": inputs}
        url = f"https://api.cloudflare.com/client/v4/accounts/{self.config['cf_account_id']}/ai/run/{model}"
        
        # 脱敏 Token
        token = self.config['cf_token']
        masked_token = token[:8] + "..." + token[-4:] if len(token) > 12 else "***"
        logger.debug(f"请求 URL: {url}")
        logger.debug(f"使用 Token: {masked_token}")
        logger.debug(f"请求体: {json.dumps(payload, ensure_ascii=False)}")
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            
            logger.info(f"HTTP 状态码: {response.status_code}")
            logger.debug(f"响应原文: {response.text}")
            
            if response.status_code >= 400:
                if response.status_code == 429:
                    retry_after = response.headers.get('Retry-After', '未知')
                    logger.error(f"触发限流 429，需等待 {retry_after} 秒后重试；响应: {response.text}")
                error_msg = f"请求失败，状态码 {response.status_code}，响应: {response.text}"
                logger.error(error_msg)
                _record_ai_call(False)
                response.raise_for_status()

            _record_ai_call(True)
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"请求异常: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"响应体: {e.response.text}")
            raise

    def ai_filter(self, description, prompt, *, accept_true=False):
        """Parse a real AI reply; never use TRUE as an API-error fallback.

        RSS calls with accept_true=True use a standalone affirmative reply as
        TRUE immediately (title + link notification). Other callers retain
        the original summary-retry behavior on pure boolean responses.
        """
        max_retries = 3
        last_error = None
        only_positive_boolean = True
        for retry_count in range(1, max_retries + 1):
            try:
                logger.info("第 %s 次调用 AI 过滤，描述: %s...", retry_count, str(description or '')[:50])
                system_prompt = str(prompt or '')
                if retry_count > 1 and isinstance(last_error, AIOnlyBooleanResponse):
                    # 只针对错误的单独 TRUE 作格式纠错，不改变用户配置的原有优惠判断范围。
                    system_prompt += (
                        "\n【输出格式纠错】刚才模型仅输出了 TRUE/YES 等判断词，无法用于推送。"
                        "请重新完整阅读标题及摘要；若确有促销，请直接写出中文总结、套餐和折扣码，"
                        "缺失的资料写‘未提供/见原文’，不可编造。"
                        "如果不是优惠活动，仅输出 FALSE。绝对不要单独输出 TRUE、YES 或 1。"
                    )
                inputs = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": description}
                ]
                output = self.workers_ai_run(self.config['model'], inputs)
                if not isinstance(output, dict) or output.get('success') is False or output.get('errors'):
                    raise ValueError("Workers AI 返回失败状态")
                response = output.get('result')
                if not isinstance(response, dict):
                    raise ValueError("Workers AI 响应缺少有效 result 字段")
                content = response.get('response')
                if not isinstance(content, str) or not content.strip():
                    choices = response.get('choices')
                    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
                        message = choices[0].get('message')
                        content = message.get('content') if isinstance(message, dict) else None
                if not isinstance(content, str):
                    raise ValueError("Workers AI 返回的正文不是文本")

                # Qwen3 等思考模型可能携带 <think> 内容；仅保留面向用户的结果。
                content = re.sub(r'<think\b[^>]*>.*?</think\s*>', '', content, flags=re.I | re.S)
                content = re.sub(r'^\s*</think\s*>', '', content, flags=re.I)
                if re.search(r'<think\b', content, flags=re.I):
                    raise ValueError("模型思考内容未正确闭合，拒绝作为摘要")
                # 旧评论提示词采用 END 后缀；只去掉位于末尾的 END，不截断正文中的单词或 URL。
                result = re.sub(r'(?i)\s+END\s*$', '', content).strip()
                if not result:
                    raise ValueError("Workers AI 返回空正文")

                # 容忍模型用引号、代码标记、标点包裹布尔答案。
                marker = re.sub(r'^[\s`*\"“”\'‘’]+|[\s`*\"“”\'‘’]+$', '', result)
                marker = re.sub(r'[\s.!。！,，;；:：]+$', '', marker).strip().casefold()
                if marker in ('true', 'yes', '1', '是', '对', '命中'):
                    if accept_true:
                        logger.info("RSS AI returned a positive boolean; title-only push requested")
                        return 'TRUE'
                    raise AIOnlyBooleanResponse("Workers AI 仅返回肯定布尔值，没有可推送的优惠内容")
                if marker in ('false', 'no', '0', '否'):
                    logger.info("AI 过滤正常返回 FALSE（未命中）")
                    return 'FALSE'

                # 正文不允许仅以布尔标签开头并把 TRUE 作为内容推送。
                result = re.sub(r'(?i)^\s*(?:TRUE|YES)\s*(?:[：:]\s*|\n+)\s*(?=\S)', '', result).strip()
                if not result:
                    raise AIOnlyBooleanResponse("Workers AI 未返回可用的优惠摘要")
                logger.info("AI 过滤成功，返回结果长度: %s", len(result))
                return result
            except Exception as e:
                last_error = e
                if not isinstance(e, AIOnlyBooleanResponse):
                    only_positive_boolean = False
                logger.warning("AI 过滤失败 (尝试 %s/%s): %s", retry_count, max_retries, e)
                if retry_count < max_retries:
                    time.sleep(1 if isinstance(e, AIOnlyBooleanResponse) else 10)

        if only_positive_boolean:
            logger.error("AI 连续 %s 次仅输出 TRUE/YES，未得到摘要", max_retries)
            raise AIOnlyBooleanResponse(f"AI 连续 {max_retries} 次只返回 TRUE/YES，没有摘要")
        logger.error("AI 过滤连续 %s 次失败，交由调用方保留待重试；最后错误：%s", max_retries, last_error)
        raise RuntimeError(f"AI 过滤失败（已重试 {max_retries} 次）：{last_error}")

    def ai_translate(self, description):
        """独立的关注用户汉化通道，失败抛异常，由爬楼层保留待重试状态。"""
        if not str(description or '').strip():
            return "（该评论没有可翻译的文字内容）"

        prompt = self.config.get('user_translation_prompt') or DEFAULT_USER_TRANSLATION_PROMPT
        last_error = None
        for attempt in range(1, 4):
            try:
                inputs = [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": description},
                ]
                output = self.workers_ai_run(self.config['model'], inputs)
                result = output.get('result') if isinstance(output, dict) else None
                if not isinstance(result, dict):
                    raise ValueError("Workers AI 响应缺少 result")
                if isinstance(result.get('response'), str):
                    translated = result['response']
                elif result.get('choices'):
                    translated = result['choices'][0]['message']['content']
                else:
                    raise ValueError("Workers AI 响应无翻译正文")
                if not isinstance(translated, str):
                    raise ValueError("Workers AI 返回非文本内容")
                # 一些思考模型会带 <think> 标签；它们不是翻译内容。
                translated = re.sub(r'<think\b[^>]*>.*?</think\s*>', '', translated, flags=re.I | re.S).strip()
                translated = re.sub(r'^</think\s*>', '', translated, flags=re.I).strip()
                if not translated or translated.casefold() in ('false', 'true', 'end'):
                    raise ValueError("Workers AI 未返回有效汉化正文")
                logger.info("关注用户名 AI 汉化成功，输出长度: %s", len(translated))
                return translated
            except Exception as exc:
                last_error = exc
                logger.warning("关注用户名 AI 汉化失败 (%s/3): %s", attempt, exc)
                if attempt < 3:
                    time.sleep(5)

        raise RuntimeError(f"AI 汉化连续 3 次失败：{last_error}")

    # ---------- 新增：测试连通性 ----------
    def test_workers_ai(self):
        """
        测试 Workers AI 连通性，发送一条简单消息。
        供 Web 接口 /api/test/workers-ai 调用，返回包含 'ok' 字段的字典。
        """
        try:
            # 简单测试 prompt
            test_inputs = [
                {"role": "user", "content": "请回复 OK"}
            ]
            logger.info("开始 Workers AI 连通性测试")
            result = self.workers_ai_run(self.config['model'], test_inputs)
            
            # 判断是否成功获得响应
            if 'result' in result:
                # 检查是否有错误字段
                if 'errors' in result and result.get('errors'):
                    error_msg = result['errors'][0].get('message', '未知错误')
                    logger.error(f"模型返回错误: {error_msg}")
                    return {"ok": False, "message": f"模型返回错误: {error_msg}", "detail": result}
                # 判断是否有内容
                content = None
                if 'response' in result['result']:
                    content = result['result']['response']
                elif 'choices' in result['result']:
                    content = result['result']['choices'][0]['message']['content']
                if content:
                    logger.info("连通性测试成功")
                    return {"ok": True, "message": "连接成功", "response": content}
                else:
                    logger.warning("响应格式无内容字段")
                    return {"ok": False, "message": "响应格式异常，缺少内容", "detail": result}
            else:
                logger.error("响应缺少 'result' 字段")
                return {"ok": False, "message": "响应缺少 'result' 字段", "detail": result}
        except Exception as e:
            logger.error(f"连通性测试异常: {e}")
            return {"ok": False, "message": str(e)}
