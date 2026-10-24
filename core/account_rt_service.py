# -*- coding: utf-8 -*-
"""账号 Web RT（ChatGPT Web session token）获取后台队列。"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any

from core import db

logger = logging.getLogger(__name__)

_WORKERS = 1  # Roxy 官方 roxynet 是全局本地端口，RT 并发会互抢/卡住，必须串行
_QUEUE_LIMIT = 200
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="account-rt")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)

_ROXYNET_FAILURE_LOCK = threading.Lock()
_ROXYNET_UNAVAILABLE_UNTIL = 0.0
_ROXYNET_LAST_ERROR = ""

_PREFERRED_RT_COOKIE_NAMES = (
    "__Secure-next-auth.session-token",
    "next-auth.session-token",
    "__Secure-authjs.session-token",
    "authjs.session-token",
    "__Secure-oai-session-token",
    "oai-session-token",
    "__Secure-openai-session-token",
)


def _profile_payload_for_proxy(proxy: str | None) -> dict | None:
    if not proxy:
        return None
    global _ROXYNET_UNAVAILABLE_UNTIL, _ROXYNET_LAST_ERROR
    now = time.time()
    with _ROXYNET_FAILURE_LOCK:
        if _ROXYNET_UNAVAILABLE_UNTIL > now:
            raise RuntimeError(
                f"Roxy roxynet 当前不可用，已暂停 RT 队列快速失败约 {int(_ROXYNET_UNAVAILABLE_UNTIL - now)} 秒；"
                f"请先打开/重启 RoxyBrowser。上次错误：{_ROXYNET_LAST_ERROR}"
            )
    from core.roxybrowser_client import (
        _maybe_start_proxy_chain,
        _normalize_proxy_url,
        _proxy_url_to_roxy_info,
        _register_official_roxynet_proxy,
        _roxy_pool_default_scheme,
    )
    source_proxy_url = _normalize_proxy_url(proxy, default_scheme=_roxy_pool_default_scheme())
    try:
        roxynet = _register_official_roxynet_proxy(source_proxy_url)
    except RuntimeError as exc:
        if "roxynet" in str(exc).lower():
            with _ROXYNET_FAILURE_LOCK:
                _ROXYNET_LAST_ERROR = str(exc)[:300]
                _ROXYNET_UNAVAILABLE_UNTIL = time.time() + 120
        raise
    if roxynet is not None:
        proxy_for_roxy, chain_handle = roxynet
    else:
        proxy_for_roxy, chain_handle = _maybe_start_proxy_chain(source_proxy_url)
    normalized_proxy_url = _normalize_proxy_url(proxy_for_roxy, default_scheme=_roxy_pool_default_scheme())
    payload = {
        "__skip_proxy_pool": True,
        "proxyInfo": _proxy_url_to_roxy_info(normalized_proxy_url),
        "proxy": normalized_proxy_url,
        "__proxy_used": source_proxy_url,
    }
    if chain_handle is not None:
        payload["__chain_handle"] = chain_handle
    logger.info("[AccountRT] 使用账号注册代理创建 Roxy 环境: source=%s roxy_proxy=%s", source_proxy_url, normalized_proxy_url)
    return payload


def _collect_cookies(driver) -> list[dict[str, Any]]:
    cookies: list[dict[str, Any]] = []
    seen = set()
    for url in ("https://chatgpt.com/", "https://auth.openai.com/"):
        try:
            driver.get(url)
            time.sleep(1.0)
            for cookie in driver.get_cookies() or []:
                key = (cookie.get("domain"), cookie.get("name"), cookie.get("path"))
                if key in seen:
                    continue
                seen.add(key)
                cookies.append(dict(cookie))
        except Exception as exc:
            logger.debug("[AccountRT] 读取 cookie 失败 url=%s: %s: %s", url, type(exc).__name__, exc)
    return cookies


def _select_web_rt_cookie(cookies: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    def val(c: dict) -> str:
        return str(c.get("value") or "").strip()

    by_name = {str(c.get("name") or ""): c for c in cookies if val(c)}
    for name in _PREFERRED_RT_COOKIE_NAMES:
        c = by_name.get(name)
        if c and len(val(c)) > 40:
            return val(c), c
    for c in cookies:
        name = str(c.get("name") or "").lower()
        value = val(c)
        if "session-token" in name and len(value) > 40:
            return value, c
    for c in cookies:
        name = str(c.get("name") or "").lower()
        value = val(c)
        if ("session" in name or "auth" in name or "oai" in name) and len(value) > 80:
            return value, c
    raise RuntimeError("已登录但未找到 Web RT/session cookie")


def _login_and_get_web_rt(*, email: str, proxy: str | None) -> dict:
    from core.email_provider import wait_for_otp
    from core.roxybrowser_client import RoxyBrowserClient
    from core.roxy_registration import (
        _build_driver,
        _center_browser_window,
        _clear_otp_inputs,
        _click_continue,
        _fetch_chatgpt_session,
        _maybe_accept,
        _preclear_chatgpt_auth_state,
        _safe_get,
        _submit_email_and_wait_next,
        _type_otp,
        _wait_after_email_otp_submit,
    )
    from config import roxybrowser as _roxy_cfg

    client = RoxyBrowserClient()
    opened = client.open_profile(payload=_profile_payload_for_proxy(proxy))
    driver = None
    try:
        driver = _build_driver(opened)
        _center_browser_window(driver)
        driver.set_page_load_timeout(int(getattr(_roxy_cfg, "ROXY_SELENIUM_TIMEOUT", 60) or 60))
        _preclear_chatgpt_auth_state(driver, reason="account_rt_start")

        _safe_get(driver, "https://chatgpt.com/auth/login", timeout=45, attempts=2, accept_hosts=("chatgpt.com", "auth.openai.com"))
        time.sleep(2.0)
        _maybe_accept(driver)
        time.sleep(0.5)

        session_info = None
        try:
            session_info = _fetch_chatgpt_session(driver, timeout=6, auto_jump_wait=3)
        except Exception:
            session_info = None

        if not (isinstance(session_info, dict) and session_info.get("accessToken")):
            max_email_rounds = 3
            for round_no in range(1, max_email_rounds + 1):
                otp_after_ts = time.time()
                # 复用注册流程更完整的邮箱提交状态机：它会处理首页壳、
                # 二段 auth.openai.com 邮箱页、cookie 弹窗和 NextAuth 回退。
                state = _submit_email_and_wait_next(driver, email, attempts=3)
                if state == "logged_in":
                    break
                if state != "otp":
                    _maybe_accept(driver)
                    if round_no >= max_email_rounds:
                        raise RuntimeError(f"提交邮箱后没有进入 OTP 页: state={state}")
                    logger.warning("[AccountRT] 提交邮箱后未进入 OTP 页，重试 %s/%s: state=%s", round_no + 1, max_email_rounds, state)
                    continue
                code = str(wait_for_otp(email, after_ts=otp_after_ts) or "").strip()
                if not code:
                    raise RuntimeError("邮箱 OTP 为空")
                logger.info("[AccountRT] 邮箱 OTP 收到：%s", code)
                _clear_otp_inputs(driver)
                _type_otp(driver, code)
                time.sleep(1.0)
                try:
                    _click_continue(driver)
                except Exception as exc:
                    logger.debug("[AccountRT] OTP 后未找到继续按钮，等待页面自动跳转: %s", str(exc)[:120])
                outcome = _wait_after_email_otp_submit(driver, timeout=45)
                if outcome == "accepted":
                    break
                if round_no >= max_email_rounds:
                    raise RuntimeError(f"邮箱 OTP 未被接受: outcome={outcome}")

            session_info = _fetch_chatgpt_session(driver, timeout=150, auto_jump_wait=25)

        access_token = str((session_info or {}).get("accessToken") or "").strip()
        if not access_token:
            raise RuntimeError("Web 登录成功后 /api/auth/session 未返回 accessToken")
        cookies = _collect_cookies(driver)
        rt, rt_cookie = _select_web_rt_cookie(cookies)
        return {
            "refresh_token": rt,
            "access_token": access_token,
            "session": session_info,
            "rt_cookie_name": rt_cookie.get("name"),
            "rt_cookie_domain": rt_cookie.get("domain"),
            "rt_cookie_path": rt_cookie.get("path"),
            "cookie_count": len(cookies),
        }
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
        try:
            client.cleanup_profile(opened)
        except Exception:
            logger.debug("[AccountRT] 清理 Roxy 环境失败", exc_info=True)


def _run_obtain(*, account_id: int, email: str, proxy: str | None, trigger: str) -> dict:
    try:
        if not db.mark_account_rt_running(account_id):
            return {"ok": False, "error": "账号已删除或 RT 状态已被重置"}
        logger.info("[AccountRT] 开始获取 Web RT: account_id=%s email=%s proxy=%s", account_id, email, proxy or "-")
        web = _login_and_get_web_rt(email=email, proxy=proxy)
        result = {
            "ok": True,
            "status": "success",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "message": f"Web RT 已获取: cookie={web.get('rt_cookie_name')}",
            "refresh_token": web.get("refresh_token"),
            "access_token": web.get("access_token"),
            "session": web.get("session") or {},
            "email": email,
            "proxy_used": proxy,
            "rt_cookie_name": web.get("rt_cookie_name"),
            "rt_cookie_domain": web.get("rt_cookie_domain"),
        }
        db.update_account_rt(account_id, result)
        logger.info("[AccountRT] 获取成功: account_id=%s email=%s cookie=%s", account_id, email, web.get("rt_cookie_name"))
        return result
    except Exception as exc:
        result = {
            "ok": False,
            "status": "failed",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"{type(exc).__name__}: {str(exc)[:500]}",
            "proxy_used": proxy,
        }
        try:
            db.update_account_rt(account_id, result)
        except Exception:
            logger.exception("[AccountRT] 写入失败状态异常: account_id=%s", account_id)
        logger.exception("[AccountRT] 获取失败: account_id=%s email=%s", account_id, email)
        return result
    finally:
        _QUEUE_SLOTS.release()


def enqueue_account_rt(*, account_id: int, email: str, proxy: str | None = None, trigger: str = "manual") -> dict:
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "error": "RT 队列已满"}
    try:
        if not db.claim_account_rt(account_id, trigger=trigger):
            _QUEUE_SLOTS.release()
            return {"accepted": False, "busy": True, "error": "该账号正在获取 RT"}
        fut = _EXECUTOR.submit(_run_obtain, account_id=account_id, email=email, proxy=proxy, trigger=trigger)
        return {"accepted": True, "busy": False, "future": fut}
    except Exception:
        _QUEUE_SLOTS.release()
        raise

