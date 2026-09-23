# -*- coding: utf-8 -*-
"""
科研通(ablesci.com) 自动签到 — 2026-09-23 修复版
==================================================
修复「无法获取CSRF令牌」：
科研通 2026-09-14 前后改版登录页，原先 <input name="_csrf"> 隐藏域已不存在，
令牌改放 <meta name="csrf-token"> 标签，并通过 JS(csrf.js) 注入表单。
另外：登录接口现在需要 图片验证码(captcha_proof) + 登录后 confirm_token 二次确认。

本版完整流程：
  1. GET  /site/login                  -> 从 meta 标签取 csrf-token（含旧版 input 兜底）
  2. POST /site/login                  -> 若返回 verify=1 要求验证码
  3. POST /site/create-password-login-captcha -> 取 captcha_id + base64 图片
  4. ddddocr 识别（失败自动重试，最多 CAPTCHA_MAX_RETRIES 次）
  5. POST /site/verify-password-login-captcha (verify_only=1) -> 换 captcha_proof
  6. POST /site/login (带 captcha_proof)  -> code=0, data.confirm_token
  7. POST /site/confirm-login (confirm_token) -> confirmed=true，登录态落 Cookie
  8. GET  /user/sign   -> 签到
  9. GET  /            -> 用户名/积分/连续天数

通知仍走 sendNotify.py（Server酱/息知/PushPlus），环境变量 ABLESCI_ACCOUNTS 不变。
"""
import os
import sys
import time
import json
import base64
import datetime
from pathlib import Path
from datetime import timezone, timedelta

import requests
from bs4 import BeautifulSoup

try:
    from zoneinfo import ZoneInfo
    ZONEINFO_AVAILABLE = True
except ImportError:
    ZONEINFO_AVAILABLE = False

ENV_ACCOUNTS = "ABLESCI_ACCOUNTS"

BASE = "https://www.ablesci.com"
LOGIN_URL = BASE + "/site/login"
CAPTCHA_CREATE_URL = BASE + "/site/create-password-login-captcha"
CAPTCHA_VERIFY_URL = BASE + "/site/verify-password-login-captcha"
CONFIRM_LOGIN_URL = BASE + "/site/confirm-login"
SIGN_URL = BASE + "/user/sign"
HOME_URL = BASE + "/"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36")

CAPTCHA_MAX_RETRIES = int(os.getenv("CAPTCHA_MAX_RETRIES", "6"))
OCR_DEBUG = os.getenv("OCR_DEBUG", "") == "1"


def load_env_file():
    script_dir = Path(__file__).parent
    env_file = script_dir / ".env"
    if not env_file.exists():
        return
    env_vars = {}
    account_lines = []
    with open(env_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                key, value = key.strip(), value.strip()
                env_vars[key] = env_vars.get(key, "") + ("\n" if key in env_vars else "") + value
            else:
                account_lines.append(line)
    for key, value in env_vars.items():
        if key not in os.environ:
            os.environ[key] = value
            print(f"已从 {env_file} 设置环境变量: {key}")
    if ENV_ACCOUNTS not in os.environ and account_lines:
        os.environ[ENV_ACCOUNTS] = "\n".join(account_lines)
        print(f"已从 {env_file} 的无键行设置 {ENV_ACCOUNTS}（共 {len(account_lines)} 个账号）")


load_env_file()


def get_beijing_time():
    if ZONEINFO_AVAILABLE:
        try:
            return datetime.datetime.now(ZoneInfo("Asia/Shanghai"))
        except Exception:
            pass
    try:
        import pytz
        return datetime.datetime.now(pytz.timezone("Asia/Shanghai"))
    except ImportError:
        pass
    return datetime.datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=8)))


def protect_privacy(text):
    if not text:
        return text
    if "@" in text:
        parts = text.split("@")
        local = parts[0][:2] + "***" if len(parts[0]) > 2 else "***"
        return f"{local}@{parts[1]}"
    return text[:2] + "***" if len(text) > 2 else "***"


def create_ocr():
    """加载 ddddocr；GitHub Actions 上 pip install ddddocr 即可"""
    try:
        import ddddocr
        return ddddocr.DdddOcr(show_ad=False)
    except Exception as e:
        print(f"[warn] ddddocr 加载失败({e})，验证码识别不可用")
        return None


class Notifier:
    def __init__(self, title="科研通签到"):
        self.log_content = []
        self.title = title
        self.notify_enabled = False
        try:
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from sendNotify import send
            self.send = send
            self.notify_enabled = True
        except Exception as e:
            print(f"[warn] 通知模块不可用: {e}")

    def log(self, message, level="info"):
        ts = get_beijing_time().strftime("%Y-%m-%d %H:%M:%S")
        symbol = {"info": "ℹ️", "success": "✅", "error": "❌", "warning": "⚠️"}.get(level, "ℹ️")
        line = f"[{ts}] {symbol} {message}"
        print(line)
        self.log_content.append(line)

    def send_notification(self):
        if not self.notify_enabled:
            return False
        try:
            self.send(self.title, "\n".join(self.log_content))
            self.log("通知发送成功", "success")
            return True
        except Exception as e:
            self.log(f"发送通知失败: {e}", "error")
            return False

    def get_content(self):
        return "\n".join(self.log_content)


class AbleSciAuto:
    def __init__(self, email, password, notifier=None):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": UA,
            "Accept-Language": "zh-CN,zh;q=0.9",
        })
        self.email = email
        self.password = password
        self.username = None
        self.points = None
        self.sign_days = None
        self.notifier = notifier if notifier else Notifier()
        self.ocr = create_ocr()
        self.csrf = ""          # 当前有效的 CSRF 令牌（服务端会轮换，需持续更新）
        self.start_time = time.time()
        self.log(f"处理账号: {protect_privacy(self.email)}", "info")

    def log(self, message, level="info"):
        self.notifier.log(message, level)

    # ---------- 基础请求 ----------
    def _xhr_headers(self, referer=BASE + "/"):
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Referer": referer,
        }
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        return headers

    def _post_json(self, url, data, referer=BASE + "/", with_csrf=True):
        headers = self._xhr_headers(referer)
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        payload = dict(data or {})
        if with_csrf and self.csrf and "_csrf" not in payload:
            payload["_csrf"] = self.csrf
        resp = self.session.post(url, data=payload, headers=headers, timeout=30)
        try:
            return resp.json(), resp
        except ValueError:
            return {"code": -1, "msg": f"响应非JSON({resp.status_code})"}, resp

    # ---------- CSRF ----------
    def get_csrf_token(self):
        """从登录页拿 CSRF 令牌：新版在 meta 标签，旧版在隐藏 input（兜底）"""
        try:
            resp = self.session.get(LOGIN_URL, timeout=30)
            if resp.status_code != 200:
                self.log(f"获取登录页失败，状态码: {resp.status_code}", "error")
                return ''
            soup = BeautifulSoup(resp.text, 'html.parser')
            meta = soup.find('meta', attrs={'name': 'csrf-token'})
            if meta and meta.get('content'):
                self.csrf = meta['content']
                return self.csrf
            inp = soup.find('input', {'name': '_csrf'})
            if inp and inp.get('value'):
                self.csrf = inp['value']
                return self.csrf
            self.log("登录页中未找到 CSRF 令牌（meta 与 input 均缺失）", "error")
        except Exception as e:
            self.log(f"获取CSRF令牌时出错: {e}", "error")
        return ''

    # ---------- 验证码 ----------
    def _solve_captcha(self):
        """生成并识别验证码，返回 (captcha_id, captcha_code)；失败返回 (None, None)"""
        if not self.ocr:
            self.log("OCR 不可用，无法过验证码", "error")
            return None, None
        data, resp = self._post_json(CAPTCHA_CREATE_URL, {}, referer=LOGIN_URL)
        if data.get("code") != 0:
            self.log(f"生成验证码失败: {data.get('msg')}", "error")
            return None, None
        captcha_id = data["data"]["captcha_id"]
        image_b64 = data["data"]["image"]
        image = base64.b64decode(image_b64.split(",", 1)[1])
        code = self.ocr.classification(image)
        if OCR_DEBUG:
            Path("captcha_debug.png").write_bytes(image)
            self.log(f"[debug] captcha_id={captcha_id} ocr={code!r}", "info")
        # 5位为标准长度；识别偶尔漏字符，可截取/补齐重试
        return captcha_id, code

    def _captcha_proof(self):
        """识别验证码并换取 captcha_proof"""
        for attempt in range(1, CAPTCHA_MAX_RETRIES + 1):
            captcha_id, code = self._solve_captcha()
            if not captcha_id:
                time.sleep(2)
                continue
            data, _ = self._post_json(CAPTCHA_VERIFY_URL, {
                "email": self.email,
                "verify_only": 1,
                "captcha_id": captcha_id,
                "captcha_code": code,
            }, referer=LOGIN_URL)
            err = (data.get("data") or {}).get("error_code")
            if data.get("code") == 0 and (data.get("data") or {}).get("captcha_proof"):
                self.log(f"验证码识别成功（第{attempt}次）", "success")
                return data["data"]["captcha_proof"]
            if err == "CAPTCHA_UNAVAILABLE":
                self.log("验证码服务暂不可用，稍后重试", "warning")
            else:
                self.log(f"验证码识别失败（第{attempt}次, 识别为 {code!r}）", "warning")
            time.sleep(1.5)
        return None

    # ---------- 登录 ----------
    def _update_csrf(self, data_obj):
        """从响应 data 中提取轮换后的 CSRF 令牌"""
        if isinstance(data_obj, dict):
            new = data_obj.get("csrf") or data_obj.get("confirm_csrf")
            if new:
                self.csrf = new

    def _do_login_post(self, csrf, extra=None):
        payload = {
            "_csrf": csrf,
            "email": self.email,
            "password": self.password,
            "remember": "1",
        }
        if extra:
            payload.update(extra)
        return self._post_json(LOGIN_URL, payload, referer=LOGIN_URL, with_csrf=False)

    def _confirm_login(self, confirm_token, confirm_csrf):
        """登录成功后二次确认，把登录态固定到 Cookie"""
        payload = {"_csrf": confirm_csrf, "confirm_token": confirm_token}
        data, _ = self._post_json(CONFIRM_LOGIN_URL, payload, referer=LOGIN_URL, with_csrf=False)
        if data.get("code") == 0 and (data.get("data") or {}).get("confirmed") is True:
            return True
        err = (data.get("data") or {}).get("error_code", "")
        self.log(f"确认登录状态失败: {data.get('msg')} ({err})", "error")
        return False

    def login(self):
        if not self.email or not self.password:
            self.log("邮箱或密码为空", "error")
            return False

        csrf = self.get_csrf_token()
        if not csrf:
            self.log("无法获取CSRF令牌", "error")
            return False

        data, resp = self._do_login_post(csrf)
        if resp.status_code != 200:
            self.log(f"登录请求失败，状态码: {resp.status_code}", "error")
            return False

        d = data.get("data") or {}
        self._update_csrf(d)

        # 直接成功（无需验证码）
        if data.get("code") == 0:
            self.log(f"登录成功: {data.get('msg')}", "success")
            confirm_token = d.get("confirm_token")
            if confirm_token:
                if not self._confirm_login(confirm_token, d.get("confirm_csrf") or self.csrf):
                    return False
                self.log("登录状态已确认", "success")
            return True

        # 需要验证码
        if d.get("error_code") == "CAPTCHA_REQUIRED" or d.get("verify") == 1 or "验证码" in (data.get("msg") or ""):
            self.log("需要图片验证码，开始自动识别...", "info")
            proof = self._captcha_proof()
            if not proof:
                self.log("未能取得有效 captcha_proof", "error")
                return False
            data, resp = self._do_login_post(self.csrf, {"captcha_proof": proof})
            d = data.get("data") or {}
            self._update_csrf(d)
            if data.get("code") == 0:
                self.log(f"登录成功: {data.get('msg')}", "success")
                confirm_token = d.get("confirm_token")
                if confirm_token:
                    if not self._confirm_login(confirm_token, d.get("confirm_csrf") or self.csrf):
                        return False
                    self.log("登录状态已确认", "success")
                return True
            # 验证码可能刚失效 -> 再走一轮
            if d.get("error_code") == "CAPTCHA_REQUIRED" or "验证" in (data.get("msg") or ""):
                self.log("验证码被拒，重新识别一次...", "warning")
                proof = self._captcha_proof()
                if proof:
                    data, resp = self._do_login_post(self.csrf, {"captcha_proof": proof})
                    d = data.get("data") or {}
                    self._update_csrf(d)
                    if data.get("code") == 0:
                        confirm_token = d.get("confirm_token")
                        if confirm_token and not self._confirm_login(
                                confirm_token, d.get("confirm_csrf") or self.csrf):
                            return False
                        self.log("登录成功（重试）", "success")
                        return True

        self.log(f"登录失败: {data.get('msg')}", "error")
        return False

    # ---------- 用户信息 / 签到 ----------
    def get_user_info(self):
        try:
            resp = self.session.get(HOME_URL, headers={"Referer": HOME_URL}, timeout=30)
            if resp.status_code != 200:
                self.log(f"获取首页失败，状态码: {resp.status_code}", "error")
                return False
            soup = BeautifulSoup(resp.text, 'html.parser')
            el = soup.select_one('.mobile-hide.able-head-user-vip-username')
            if el:
                self.username = el.text.strip()
                self.log(f"用户名: {protect_privacy(self.username)}", "info")
            else:
                self.log("无法定位用户名元素", "warning")
            el = soup.select_one('#user-point-now')
            if el:
                self.points = el.text.strip()
                self.log(f"当前积分: {self.points}", "info")
            el = soup.select_one('#sign-count')
            if el:
                self.sign_days = el.text.strip()
                self.log(f"连续签到天数: {self.sign_days}", "info")
            return True
        except Exception as e:
            self.log(f"获取用户信息时出错: {e}", "error")
        return False

    def sign_in(self):
        try:
            resp = self.session.get(SIGN_URL, headers=self._xhr_headers(), timeout=30)
            if resp.status_code != 200:
                self.log(f"签到请求失败，状态码: {resp.status_code}", "error")
                return False
            try:
                result = resp.json()
            except ValueError:
                self.log("签到响应不是有效的JSON", "error")
                return False
            if result.get("code") == 0:
                self.log(f"签到成功: {result.get('msg')}", "success")
                d = result.get("data") or {}
                if "points" in d:
                    self.points = d["points"]
                    self.log(f"更新积分: {self.points}", "info")
                if "sign_days" in d:
                    self.sign_days = d["sign_days"]
                    self.log(f"更新连续签到天数: {self.sign_days}", "info")
                return True
            msg = result.get('msg', '')
            if "已" in msg and "签到" in msg:
                self.log(f"今日已签到: {msg}", "info")
                return True
            self.log(f"签到失败: {msg}", "error")
        except Exception as e:
            self.log(f"签到过程中出错: {e}", "error")
        return False

    def display_summary(self, is_before_sign=False):
        elapsed = round(time.time() - self.start_time, 2)
        title = "签到前信息" if is_before_sign else "签到后信息"
        self.log("=" * 50)
        self.log(f"用户 {protect_privacy(self.username)} {title}:")
        if self.username:
            self.log(f"  • 用户名: {protect_privacy(self.username)}")
        if self.points:
            self.log(f"  • 当前积分: {self.points}")
        if self.sign_days:
            self.log(f"  • 连续签到: {self.sign_days}天")
        self.log(f"  • 执行耗时: {elapsed}秒")
        self.log("=" * 50)
        self.log("")

    def run(self):
        if self.login():
            self.get_user_info()
            self.display_summary(is_before_sign=True)
            if self.sign_in():
                self.log("签到完成，刷新用户信息...", "info")
                time.sleep(2)
                self.get_user_info()
                self.display_summary(is_before_sign=False)
        return self.notifier.get_content()


def get_accounts():
    accounts_env = os.getenv(ENV_ACCOUNTS)
    if not accounts_env:
        return []
    accounts = []
    for line in accounts_env.splitlines():
        line = line.strip()
        if not line:
            continue
        if ";" in line:
            accounts.extend(line.split(";"))
        elif "," in line:
            accounts.extend(line.split(","))
        else:
            accounts.append(line)
    valid = []
    for account in accounts:
        account = account.strip()
        if not account:
            continue
        if ":" in account:
            email, password = account.split(":", 1)
        elif "|" in account:
            email, password = account.split("|", 1)
        else:
            print(f"警告：跳过格式错误的账号项: {account[:6]}***")
            continue
        email, password = email.strip(), password.strip()
        if email and password:
            valid.append((email, password))
        else:
            print("警告：账号或密码为空")
    return valid


def main():
    global_notifier = Notifier("科研通多账号签到")
    global_notifier.log("科研通多账号签到任务开始", "info")
    accounts = get_accounts()
    if not accounts:
        global_notifier.log("未找到有效的账号配置", "error")
        global_notifier.log(f"请设置环境变量 {ENV_ACCOUNTS}，格式为：邮箱1:密码1[换行]邮箱2:密码2", "warning")
        if global_notifier.notify_enabled:
            global_notifier.send_notification()
        return
    global_notifier.log(f"找到 {len(accounts)} 个账号", "info")
    for i, (email, password) in enumerate(accounts, 1):
        global_notifier.log(f"\n===== 开始处理第 {i}/{len(accounts)} 个账号 =====", "info")
        AbleSciAuto(email, password, notifier=global_notifier).run()
        global_notifier.log(f"===== 完成第 {i}/{len(accounts)} 个账号处理 =====", "info")
    global_notifier.log("\n===== 所有账号处理完成 =====", "info")
    if global_notifier.notify_enabled:
        global_notifier.send_notification()


if __name__ == "__main__":
    main()
