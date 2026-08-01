import json
import requests
import os
import shutil
import time
import logging
import threading
from datetime import datetime

# ---------- 配置日志 ----------
LOG_DIR = "logs"  # 日志文件夹
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, f"ai_filter_{datetime.now().strftime('%Y%m%d')}.log")

# ---------- AI 调用统计（按天） ----------
_AI_STATS_FILE = os.path.join(LOG_DIR, "ai_stats.json")
_ai_stats_lock = threading.Lock()
_ai_stats = {"date": "", "calls": 0, "failures": 0}


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

    def ai_filter(self, description, prompt):
        max_retries = 3
        for retry_count in range(1, max_retries + 1):
            try:
                logger.info(f"第 {retry_count} 次调用 AI 过滤，描述: {description[:50]}...")
                inputs = [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": description}
                ]
                output = self.workers_ai_run(self.config['model'], inputs)
                
                # 兼容响应格式
                if 'result' in output:
                    if 'response' in output['result']:
                        content = output['result']['response']
                    elif 'choices' in output['result']:
                        content = output['result']['choices'][0]['message']['content']
                    else:
                        logger.error("未知的响应格式: " + json.dumps(output, ensure_ascii=False))
                        raise ValueError("Unknown response format")
                else:
                    logger.error("响应缺少 'result' 字段: " + json.dumps(output, ensure_ascii=False))
                    raise ValueError("Missing 'result' in response")
                
                result = content.split('END')[0]
                logger.info(f"AI 过滤成功，返回结果长度: {len(result)}")
                return result
            except Exception as e:
                logger.warning(f"AI 过滤失败 (尝试 {retry_count}/{max_retries}): {e}")
                if retry_count >= max_retries:
                    logger.error(f"AI 过滤已重试 {max_retries} 次仍失败，跳过")
                    return "true"
                time.sleep(10)

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
