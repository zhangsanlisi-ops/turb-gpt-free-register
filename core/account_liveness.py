# -*- coding: utf-8 -*-
"""已注册账号查活：优先复用已有 AT 预热后走 reauth OTP，成功刷新 AT 即视为正常。"""
import logging
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode

from core import db
from core.session import BrowserSession
from core.codex_oauth import _account_registration_password, _account_totp_secret, _account_totp_code
from core.humanize import delay as human_delay
from core.chatgpt_auth import get_csrf_token, signin_openai
from core.openai_auth import (
    follow_authorize,
    send_email_otp,
    validate_email_otp,
    EmailOtpInvalidError,
    AccountUnusableError,
    detect_account_unusable_text,
)
from core.account_export import (
    _follow_reauth,
    _trigger_reauth,
    _validate_reauth_otp,
    fetch_session,
    follow_oauth_callback,
)
from core.email_provider import wait_for_otp

logger = logging.getLogger(__name__)
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"
_RUNNING: set[str] = set()
_RUNNING_LOCK = threading.Lock()

# 查活网络预检失败（403/429/代理/超时等）多为出口 IP 被 CF 标记或代理池抖动，
# 视为可换新 IP 重试；账号本身问题（废号/邮箱错误等）不重试。
_RETRYABLE_NETWORK_HINTS = (
    "403", "429", "502", "503", "504",
    "proxy", "socks", "timeout", "timed out",
    "connection", "closed", "reset",
)

_SESSION_FINGERPRINT_KEYS = {
    "device_id",
    "sentinel_sid",
    "oai_session_id",
    "auth_session_logging_id",
    "datadog_trace_id",
    "datadog_parent_id",
    "react_listening_key",
    "react_container_key",
    "react_resources_key",
}


def _is_retryable_network_error(exc: BaseException) -> bool:
    if isinstance(exc, AccountUnusableError):
        return False
    text = str(exc or "").lower()
    return any(h in text for h in _RETRYABLE_NETWORK_HINTS)


def _network_preflight_with_retry(email: str, proxy: str | None, max_attempts: int = 4) -> tuple[BrowserSession, str]:
    """CSRF → Signin 备用预检；失败时重新建立会话。

    `/api/auth/providers` 只是 NextAuth 的发现接口，signin 端点并不依赖它返回的
    内容。实际运行中该接口很容易先被 Cloudflare 拦截，如果把它作为硬门槛，后续
    本来可用的 CSRF/授权链永远不会执行。因此查活备用链不再把 providers 当作
    必经步骤。

    这里必须原样传递 ``proxy``：``None`` 表示按配置选代理，空字符串表示明确
    直连。之前用 ``proxy if proxy else None`` 把直连兜底误变成了再次抽取代理。
    """
    session: BrowserSession | None = None
    last_exc: BaseException | None = None
    seed = f"account:{email.lower()}"
    for attempt in range(1, max_attempts + 1):
        if session is not None:
            try:
                session.session.close()
            except Exception:
                pass
        # 保留 None / "" 的语义差异：显式空字符串必须是真直连。
        session = BrowserSession(proxy=proxy, fingerprint_seed=seed)
        logger.info(
            "[查活] 会话创建完成：proxy=%s device_id=%s（网络预检第 %s/%s 次）",
            session.proxy or "配置随机/直连", session.device_id, attempt, max_attempts,
        )
        logger.info("[查活] 指纹摘要：%s", session.fingerprint_summary_text())
        try:
            csrf = get_csrf_token(session)
            authorize_url = signin_openai(session, csrf, email)
            return session, authorize_url
        except Exception as exc:
            last_exc = exc
            if attempt >= max_attempts or not _is_retryable_network_error(exc):
                try:
                    session.session.close()
                except Exception:
                    pass
                raise
            logger.warning(
                "[查活] 网络预检失败（%s/%s），重新建立会话重试：%s",
                attempt, max_attempts, str(exc)[:200],
            )
            time.sleep(2)
    raise RuntimeError(f"网络预检多次失败：{last_exc}")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _safe_fingerprint_for_account(session: BrowserSession) -> dict:
    """账号里只记录运行环境画像，不保存会话/设备标识。"""
    fp = session.fingerprint_summary()
    return {k: v for k, v in fp.items() if k not in _SESSION_FINGERPRINT_KEYS}


def _safe_fingerprint_text_for_account(session: BrowserSession) -> str:
    fp = _safe_fingerprint_for_account(session)
    parts = [
        f"proxy={BrowserSession._short_value(fp.get('proxy') or 'direct', 36)}",
        f"ua={BrowserSession._short_value(fp.get('user_agent'), 72)}",
        f"lang={fp.get('accept_language')}",
        f"tz={fp.get('timezone_iana')}({fp.get('timezone_offset_minutes')})",
        f"screen={fp.get('screen_width')}x{fp.get('screen_height')}@{fp.get('device_pixel_ratio')}",
        f"cpu={fp.get('hardware_concurrency')}",
        f"mem={fp.get('device_memory')}",
        f"geo={fp.get('geo_country') or '?'}:{fp.get('geo_city') or '?'}",
    ]
    return " ".join(parts)


def _extract_continue_url(result: dict | None) -> str:
    if not isinstance(result, dict):
        return ""
    page = result.get("page") or {}
    page = page if isinstance(page, dict) else {}
    return str(
        result.get("continue_url")
        or result.get("external_url")
        or result.get("url")
        or page.get("continue_url")
        or page.get("external_url")
        or page.get("url")
        or ""
    ).strip()


def _extract_factor_id(result: dict | None, continue_url: str) -> str:
    if isinstance(result, dict):
        page = result.get("page") or {}
        page = page if isinstance(page, dict) else {}
        payload = page.get("payload") or {}
        if isinstance(payload, dict):
            factor_id = str(payload.get("factor_id") or "").strip()
            if factor_id:
                return factor_id
        if isinstance(page.get("payload"), dict):
            factor_id = str(page["payload"].get("factor_id") or "").strip()
            if factor_id:
                return factor_id
    if "/mfa-challenge/" in continue_url:
        return continue_url.rstrip("/").rsplit("/", 1)[-1]
    return ""


def _password_verify(session: BrowserSession, password: str) -> dict:
    from core.openai_auth import build_sentinel_header, request_sentinel_token

    sentinel_resp = request_sentinel_token(session, "password_verify")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "password_verify")
    headers = session.get_auth_headers(referer="https://auth.openai.com/log-in/password")
    headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
    resp = session.post(
        "https://auth.openai.com/api/accounts/password/verify",
        headers=headers,
        data=json.dumps({"password": password}),
        allow_redirects=False,
    )
    resp.raise_for_status()
    return resp.json()


def _mfa_issue_challenge(session: BrowserSession, factor_id: str) -> dict:
    headers = session.get_auth_headers(referer="https://auth.openai.com/mfa-challenge")
    headers.pop("openai-sentinel-token", None)
    headers.pop("openai-sentinel-so-token", None)
    resp = session.post(
        "https://auth.openai.com/api/accounts/mfa/issue_challenge",
        headers=headers,
        data=json.dumps({"id": factor_id, "type": "totp", "force_fresh_challenge": False}),
        allow_redirects=False,
    )
    resp.raise_for_status()
    return resp.json()


def _mfa_verify(session: BrowserSession, factor_id: str, code: str) -> dict:
    headers = session.get_auth_headers(referer="https://auth.openai.com/mfa-challenge")
    headers.pop("openai-sentinel-token", None)
    headers.pop("openai-sentinel-so-token", None)
    resp = session.post(
        "https://auth.openai.com/api/accounts/mfa/verify",
        headers=headers,
        data=json.dumps({"id": factor_id, "type": "totp", "code": code}),
        allow_redirects=False,
    )
    resp.raise_for_status()
    return resp.json()


def _follow_continue_and_fetch(session: BrowserSession, continue_url: str, *, referer: str) -> dict:
    follow_oauth_callback(session, continue_url, referer=referer)
    return fetch_session(session)


def _stored_access_token(email: str) -> str:
    """读取本地账号已有 AT，用于先预热登录态再走稳定的 reauth 链。"""
    try:
        account = db.get_account_by_email(email)
        return str((account or {}).get("access_token") or "").strip()
    except Exception as exc:
        logger.debug("[查活] 读取已有 accessToken 失败，改走备用登录链：%s: %s", type(exc).__name__, exc)
        return ""


def _clear_optional_bootstrap_circuit(session: BrowserSession) -> None:
    """清理可选登录态预热造成的本地熔断，不影响后续正式认证请求。

    authenticated_bootstrap 是 best-effort 预热，其中个别旧接口返回 403 不等于
    reauth 链不可用；BrowserSession 的通用熔断器若保留该状态，会直接拦截后续
    `/api/auth/csrf`，导致稳定的 2FA 链也无法开始。
    """
    reset = getattr(session, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
        return
    if getattr(session, "blocked_until", 0.0):
        session.blocked_until = 0.0
        session.blocked_reason = ""


def _warm_authenticated_session(session: BrowserSession, access_token: str) -> None:
    """复用 2FA 已验证的登录态预热流程。预热失败不直接判定账号死亡。"""
    if not access_token:
        return
    from core.chatgpt_bootstrap import authenticated_bootstrap

    try:
        logger.info("[查活] 使用已有 accessToken 预热登录态...")
        authenticated_bootstrap(session, access_token, strict=False)
        logger.info("[查活] accessToken 预热完成，继续走 reauth OTP")
    except Exception as exc:
        # strict=False 已经会吞掉大部分单接口错误；这里仅兜住初始化异常。
        logger.warning("[查活] accessToken 预热失败，继续走 reauth OTP：%s: %s", type(exc).__name__, str(exc)[:180])
    finally:
        _clear_optional_bootstrap_circuit(session)


def _check_stored_access_token(session: BrowserSession, access_token: str) -> dict | None:
    """用已有 AT 做一次只读查活，避免每次查活都触发完整 reauth。

    ``/backend-api/me`` 是已登录 Web 会话的轻量身份接口。只有拿到 2xx 且可解析
    的身份信息才判定存量 AT 有效；其它状态一律返回 ``None``，交给原有重认证链
    处理，不能把网络/CF 问题误标为活号。
    """
    if not access_token:
        return None
    token = access_token if access_token.lower().startswith("bearer ") else f"Bearer {access_token}"
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers["authorization"] = token
    try:
        response = session.get("https://chatgpt.com/backend-api/me", headers=headers)
        if not 200 <= int(response.status_code) < 300:
            logger.info("[查活] 现有 accessToken 验证未通过：HTTP %s，转重认证", response.status_code)
            return None
        payload = response.json()
        if not isinstance(payload, dict) or not (payload.get("email") or payload.get("id") or payload.get("user")):
            logger.info("[查活] 现有 accessToken 验证响应缺少身份字段，转重认证")
            return None
        logger.info("[查活] 现有 accessToken 有效，跳过 reauth/OTP")
        return payload
    except Exception as exc:
        logger.info("[查活] 现有 accessToken 验证异常，转重认证：%s: %s", type(exc).__name__, str(exc)[:160])
        return None
    finally:
        _clear_optional_bootstrap_circuit(session)


def _exception_response_text(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    return str(getattr(response, "text", "") or "")


def _exception_status_code(exc: BaseException) -> int | None:
    response = getattr(exc, "response", None)
    try:
        status = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        return None
    return status or None


def _is_access_blocked_error(exc: BaseException) -> bool:
    """Return true for an edge/access denial that cannot prove account state.

    A 403 is only actionable as a deactivated account when its response body
    contains one of the explicit account-unusable markers (handled before this
    helper is consulted).  Otherwise it is an inconclusive access denial, not
    a failed liveness check.  In particular, do not retry it through alternate
    network routes: that does not establish account health and can amplify a
    provider-side block.
    """
    return _exception_status_code(exc) in {403, 429}


def _is_permanent_pickup_error(exc: BaseException) -> bool:
    """取码 URL/token 已失效，重发 OTP 或 after_ts=0 回退也救不回来。"""
    text = str(exc)
    markers = (
        "取件地址里的邮箱/密钥无效",
        "取件地址无效",
        "取件地址已失效",
        "邮件地址或密钥无效",
        "邮件地址或访问密钥无效",
        "访问密钥无效",
        "mailbox token",
    )
    return any(marker in text for marker in markers)


def _validate_reauth_with_retry(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    max_otp_attempts: int = 3,
    email_source: str | None = None,
) -> str:
    """提交 reauth OTP；验证码错误时重新发送并重新取码。"""
    current_otp: str | None = None
    rejected_otps: set[str] = set()
    last_exc: Exception | None = None
    for attempt in range(1, max_otp_attempts + 1):
        try:
            if current_otp is None:
                logger.info("[查活] 等待重认证 OTP：%s（第 %s/%s 次）", email, attempt, max_otp_attempts)
                current_otp = wait_for_otp(
                    email,
                    after_ts=otp_after_ts,
                    email_source=email_source,
                    exclude_codes=rejected_otps,
                )
            human_delay("otp_input")
            continue_url = _validate_reauth_otp(session, current_otp)
            if not continue_url:
                raise RuntimeError("重认证 OTP 验证响应缺少 continue_url")
            return str(continue_url)
        except AccountUnusableError:
            raise
        except Exception as exc:
            last_exc = exc
            body = _exception_response_text(exc)
            dead_code = detect_account_unusable_text(body) or detect_account_unusable_text(str(exc))
            if dead_code:
                raise AccountUnusableError(
                    f"账号已废弃（{dead_code}），邮箱不可再用",
                    error_code=dead_code,
                ) from exc

            status = _exception_status_code(exc)
            # reauth validate 的 403 可能是 Cloudflare/出口拦截；不要在同一已熔断
            # 会话上反复发送 OTP，交给上层的直连兜底处理。
            retryable_otp = status in (400, 401, 422)
            if attempt >= max_otp_attempts or not retryable_otp:
                raise
            logger.warning(
                "[查活] 重认证 OTP 无效/过期，重新发送后再取（%s/%s）：%s",
                attempt,
                max_otp_attempts,
                str(exc)[:180],
            )
            send_email_otp(session)
            otp_after_ts = time.time()
            if current_otp:
                rejected_otps.add(current_otp)
            current_otp = None
            time.sleep(1)
    raise last_exc if last_exc else RuntimeError("重认证 OTP 验证失败")


def _login_via_reauth(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """按 2FA 已验证链路重新认证并刷新 ChatGPT session。"""
    auth_url = _trigger_reauth(session, email)
    logger.info("[查活] reauth authorize URL 已获取")
    human_delay("api")
    final_url = _follow_reauth(session, auth_url)
    dead_code = detect_account_unusable_text(final_url)
    if dead_code:
        raise AccountUnusableError(f"账号已废弃（{dead_code}）", error_code=dead_code)
    human_delay("navigate")
    logger.info("[查活] 已跟随 reauth authorize URL，开始等待邮箱 OTP")
    continue_url = _validate_reauth_with_retry(
        session,
        email,
        otp_after_ts,
        email_source=email_source,
    )
    logger.info("[查活] reauth OTP 验证通过，开始交换新 token")
    human_delay("api")
    return _follow_continue_and_fetch(
        session,
        continue_url,
        referer="https://auth.openai.com/email-verification",
    )


def _browser_fetch(page, url: str, *, method: str = "GET", headers: dict | None = None, body: str | None = None) -> dict:
    """在 RoxyBrowser 页面上下文里发起 fetch，复用浏览器网络栈/cookie。"""
    script = """async ({url, method, headers, body}) => {
          const r = await fetch(url, {
            method,
            headers: headers || {},
            body: body === null ? undefined : body,
            credentials: 'include',
          });
          const text = await r.text();
          return {status: r.status, url: r.url, text, headers: Object.fromEntries(r.headers.entries())};
        }"""
    payload = {"url": url, "method": method, "headers": headers or {}, "body": body}
    # 首页的延迟跳转会销毁 evaluate 的 execution context。只对幂等 GET
    # 重试；POST 可能已被服务端接收，不能盲目重放。
    for attempt in range(3 if method.upper() == "GET" else 1):
        try:
            return page.evaluate(script, payload)
        except Exception as exc:
            if "Execution context was destroyed" not in str(exc) or attempt >= 2 or method.upper() != "GET":
                raise
            logger.warning("[查活][Roxy] 页面跳转打断 GET fetch，等待新页面后重试：%s", url)
            page.wait_for_load_state("domcontentloaded", timeout=15000)
            time.sleep(0.2)


def _wait_for_reauth_otp_with_latest_fallback(
    email: str,
    *,
    after_ts: float,
    email_source: str | None,
    exclude_codes: set[str],
) -> str:
    """等待 reauth OTP；取件服务时间戳偏旧时回退到最新未拒绝验证码。"""
    try:
        return wait_for_otp(
            email,
            after_ts=after_ts,
            max_wait=75,
            poll_interval=5,
            email_source=email_source,
            exclude_codes=exclude_codes,
        )
    except Exception as exc:
        if _is_permanent_pickup_error(exc):
            raise
        logger.warning("[查活][Roxy] 新验证码按时间戳等待失败，回退读取最新未拒绝验证码：%s: %s", type(exc).__name__, str(exc)[:180])
        return wait_for_otp(
            email,
            after_ts=0,
            max_wait=35,
            poll_interval=5,
            email_source=email_source,
            exclude_codes=exclude_codes,
        )


def _roxy_send_reauth_email_otp(page) -> float:
    """在 auth.openai.com OTP 页面显式请求重新发送验证码。"""
    sent_at = time.time()
    try:
        resp = _browser_fetch(
            page,
            "https://auth.openai.com/api/accounts/email-otp/send",
            headers={"accept": "application/json, text/plain, */*"},
        )
        status = int(resp.get("status") or 0)
        if 200 <= status < 300:
            logger.info("[查活][Roxy] 已显式请求发送 reauth 邮箱 OTP：HTTP %s", status)
        else:
            # 该接口偶发非 2xx，但 authorize 落页本身也可能已经触发邮件；
            # 因此这里只记录，不立即中断。
            logger.warning("[查活][Roxy] 显式发送 reauth OTP 返回 HTTP %s：%s", status, str(resp.get("text") or "")[:180])
    except Exception as exc:
        logger.warning("[查活][Roxy] 显式发送 reauth OTP 异常，继续等待 authorize 自动邮件：%s: %s", type(exc).__name__, str(exc)[:160])
    return sent_at


def _roxy_goto_reauth_authorize(page, auth_url: str):
    """打开 reauth authorize URL；兼容 Chromium 重定向导致的 ERR_ABORTED。"""
    try:
        return page.goto(str(auth_url), wait_until="domcontentloaded", timeout=60000)
    except Exception as exc:
        text = str(exc)
        current_url = str(getattr(page, "url", "") or "")
        if "ERR_ABORTED" in text and (
            "auth.openai.com/email-verification" in current_url
            or "auth.openai.com" in current_url
        ):
            logger.warning("[查活][Roxy] authorize 导航被中止但已到 auth 页面，继续：url=%s err=%s", current_url, text[:180])
            return None
        logger.warning("[查活][Roxy] authorize 首次导航失败，改用 commit 重试：%s", text[:180])
        try:
            return page.goto(str(auth_url), wait_until="commit", timeout=60000)
        except Exception as retry_exc:
            retry_text = str(retry_exc)
            current_url = str(getattr(page, "url", "") or "")
            if "ERR_ABORTED" in retry_text and (
                "auth.openai.com/email-verification" in current_url
                or "auth.openai.com" in current_url
            ):
                logger.warning("[查活][Roxy] authorize commit 重试被中止但已到 auth 页面，继续：url=%s err=%s", current_url, retry_text[:180])
                return None
            raise


def _login_via_roxy_browser_reauth(
    email: str,
    *,
    proxy: str | None = None,
    email_source: str | None = None,
) -> tuple[dict, dict]:
    """使用 RoxyBrowser Chromium 网络栈执行 reauth/OTP，刷新过期 AT。"""
    try:
        from core.chatgpt_plan import _roxy_plan_proxy_payload
        from core.roxybrowser_client import RoxyBrowserClient, _mask_proxy as _roxy_mask_proxy
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError(f"RoxyBrowser reauth 依赖不可用: {type(exc).__name__}: {str(exc)[:160]}") from exc

    client = RoxyBrowserClient()
    opened = None
    browser = None
    rejected_codes: set[str] = set()
    proxy_for_roxy = str(proxy or "").strip()
    try:
        payload = _roxy_plan_proxy_payload(proxy_for_roxy)
        opened = client.open_profile(payload=payload or None)
        connect_target = str(opened.ws_endpoint or opened.debugger_address or "").strip()
        if connect_target and not connect_target.startswith(("ws://", "wss://", "http://", "https://")):
            connect_target = f"http://{connect_target}"
        if not connect_target:
            raise RuntimeError("RoxyBrowser open 未返回 CDP 调试地址")
        meta = {
            "profile_id": opened.profile_id,
            "proxy_used": _roxy_mask_proxy(proxy_for_roxy) if proxy_for_roxy else None,
            "transport": "roxy_browser",
        }
        logger.info("[查活][Roxy] 打开 RoxyBrowser reauth：profile=%s proxy=%s", opened.profile_id, meta.get("proxy_used") or "-")
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(connect_target)
            context = browser.contexts[0] if browser.contexts else browser.new_context()
            page = context.new_page()
            page.set_default_timeout(45000)
            resp = page.goto("https://chatgpt.com/", wait_until="domcontentloaded", timeout=45000)
            logger.info("[查活][Roxy] chatgpt.com 首页打开：HTTP %s url=%s", getattr(resp, "status", None), page.url)

            csrf_resp = _browser_fetch(page, "https://chatgpt.com/api/auth/csrf", headers={"accept": "application/json"})
            if not 200 <= int(csrf_resp.get("status") or 0) < 300:
                raise RuntimeError(f"RoxyBrowser CSRF HTTP {csrf_resp.get('status')}: {str(csrf_resp.get('text') or '')[:180]}")
            csrf_token = (json.loads(csrf_resp.get("text") or "{}") or {}).get("csrfToken")
            if not csrf_token:
                raise RuntimeError(f"RoxyBrowser CSRF 响应缺少 csrfToken: {str(csrf_resp.get('text') or '')[:180]}")

            signin_url = "https://chatgpt.com/api/auth/signin/openai?" + urlencode({
                "connection": "password",
                "login_hint": email,
                "reauth": "password",
                "max_age": "0",
            })
            signin_resp = _browser_fetch(
                page,
                signin_url,
                method="POST",
                headers={"content-type": "application/x-www-form-urlencoded", "accept": "application/json"},
                body=urlencode({
                    "callbackUrl": "https://chatgpt.com/?action=enable&factor=totp",
                    "csrfToken": csrf_token,
                    "json": "true",
                }),
            )
            if not 200 <= int(signin_resp.get("status") or 0) < 300:
                raise RuntimeError(f"RoxyBrowser signin HTTP {signin_resp.get('status')}: {str(signin_resp.get('text') or '')[:220]}")
            auth_url = (json.loads(signin_resp.get("text") or "{}") or {}).get("url")
            if not auth_url:
                raise RuntimeError(f"RoxyBrowser signin 未返回 authorize URL: {str(signin_resp.get('text') or '')[:220]}")

            otp_after_ts = time.time()
            auth_resp = _roxy_goto_reauth_authorize(page, str(auth_url))
            logger.info("[查活][Roxy] reauth authorize 落点：HTTP %s url=%s", getattr(auth_resp, "status", None), page.url)
            dead_code = detect_account_unusable_text(page.url)
            if dead_code:
                raise AccountUnusableError(f"账号已废弃（{dead_code}）", error_code=dead_code)
            otp_after_ts = _roxy_send_reauth_email_otp(page)

            last_error = None
            for attempt in range(1, 4):
                try:
                    code = _wait_for_reauth_otp_with_latest_fallback(
                        email,
                        after_ts=otp_after_ts,
                        email_source=email_source,
                        exclude_codes=rejected_codes,
                    )
                except Exception as otp_exc:
                    last_error = f"{type(otp_exc).__name__}: {str(otp_exc)[:220]}"
                    if _is_permanent_pickup_error(otp_exc):
                        logger.warning("[查活][Roxy] 取码地址永久失效，停止重发 OTP：%s", last_error)
                        raise RuntimeError(f"RoxyBrowser reauth OTP 取码地址无效: {otp_exc}") from otp_exc
                    logger.warning("[查活][Roxy] 获取 reauth OTP 失败（第 %s/3 次），重新发送后继续：%s", attempt, last_error)
                    if attempt >= 3:
                        break
                    otp_after_ts = _roxy_send_reauth_email_otp(page)
                    continue
                logger.info("[查活][Roxy] 提交 reauth OTP（第 %s/3 次）", attempt)
                validate_resp = _browser_fetch(
                    page,
                    "https://auth.openai.com/api/accounts/email-otp/validate",
                    method="POST",
                    headers={"content-type": "application/json", "accept": "application/json"},
                    body=json.dumps({"code": code}),
                )
                status = int(validate_resp.get("status") or 0)
                text = str(validate_resp.get("text") or "")
                if 200 <= status < 300:
                    data = json.loads(text or "{}")
                    continue_url = data.get("continue_url")
                    if not continue_url:
                        raise RuntimeError(f"RoxyBrowser OTP 验证响应缺少 continue_url: {text[:220]}")
                    try:
                        callback_resp = page.goto(str(continue_url), wait_until="domcontentloaded", timeout=60000)
                    except Exception as callback_exc:
                        # OAuth callback may have set the session cookie even if
                        # the subsequent page load stalls. Do not discard a
                        # completed OTP login solely on a navigation timeout;
                        # verify the session below before deciding it failed.
                        if "Timeout" not in str(callback_exc) or "chatgpt.com" not in str(getattr(page, "url", "")):
                            raise
                        callback_resp = None
                        logger.warning("[查活][Roxy] OAuth callback 导航超时，继续验证 session：%s", str(callback_exc)[:160])
                    logger.info("[查活][Roxy] OAuth callback 完成：HTTP %s url=%s", getattr(callback_resp, "status", None), page.url)
                    # OAuth callback 之后，ChatGPT 的边缘节点偶尔先返回
                    # 403 HTML 挑战页；立即把账号判成查活失败会丢掉已经
                    # 成功完成的 OTP 登录。只重试幂等的 session GET，期间
                    # 回到首页让浏览器完成 cookie/challenge 跳转。
                    session_resp = {}
                    for session_attempt in range(1, 4):
                        session_resp = _browser_fetch(
                            page, "https://chatgpt.com/api/auth/session",
                            headers={"accept": "application/json"},
                        )
                        session_status = int(session_resp.get("status") or 0)
                        if session_status != 403:
                            break
                        logger.warning(
                            "[查活][Roxy] OAuth 后 session GET 返回 403，等待页面稳定再重试 %s/3",
                            session_attempt,
                        )
                        if session_attempt < 3:
                            try:
                                page.goto("https://chatgpt.com/", wait_until="domcontentloaded", timeout=45000)
                            except Exception as nav_exc:
                                logger.warning("[查活][Roxy] session 403 后首页导航失败：%s", str(nav_exc)[:160])
                            time.sleep(2 * session_attempt)
                    if not 200 <= int(session_resp.get("status") or 0) < 300:
                        raise RuntimeError(f"RoxyBrowser session HTTP {session_resp.get('status')}: {str(session_resp.get('text') or '')[:220]}")
                    session_info = json.loads(session_resp.get("text") or "{}")
                    if not session_info.get("accessToken"):
                        raise RuntimeError(f"RoxyBrowser session 未拿到 accessToken: {str(session_info)[:220]}")
                    return session_info, meta
                rejected_codes.add(str(code))
                last_error = f"HTTP {status}: {text[:220]}"
                dead_code = detect_account_unusable_text(text)
                if dead_code:
                    raise AccountUnusableError(
                        f"账号已废弃（{dead_code}）", error_code=dead_code,
                    )
                logger.warning("[查活][Roxy] reauth OTP 验证失败（第 %s/3 次）：%s", attempt, last_error)
                if status not in (400, 401, 422):
                    break
                otp_after_ts = _roxy_send_reauth_email_otp(page)
            raise RuntimeError(f"RoxyBrowser reauth OTP 未通过: {last_error or 'unknown'}")
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        if opened is not None:
            try:
                client.cleanup_profile(opened)
            except Exception:
                logger.debug("[查活][Roxy] 清理 RoxyBrowser Profile 失败", exc_info=True)


def _login_via_email_otp(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """完成邮箱 OTP 登录，并跟随 OAuth callback 后拉取 ChatGPT session。"""
    validate_result = _validate_with_retry(
        session,
        email,
        otp_after_ts,
        email_source=email_source,
    )
    page = validate_result.get("page") if isinstance(validate_result, dict) else {}
    page = page if isinstance(page, dict) else {}
    page_type = str(page.get("type") or "")
    continue_url = _extract_continue_url(validate_result)
    if not continue_url:
        raise RuntimeError(f"OTP 登录成功但没有 OAuth continue_url: {validate_result}")
    if "about-you" in str(continue_url) or page_type in {"about_you", "about-you"}:
        raise RuntimeError(f"该邮箱登录后进入资料页，疑似不是完整已注册账号: page_type={page_type}, continue_url={continue_url}")
    logger.info("[查活] 邮箱 OTP 验证完成，开始跟随 OAuth callback")
    return _follow_continue_and_fetch(session, continue_url, referer="https://auth.openai.com/email-verification")


def _login_via_password_or_otp(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """优先密码登录；如进入 MFA challenge 则自动用 TOTP 完成。"""
    password = _account_registration_password(email)
    if not password:
        logger.info("[查活] 未找到注册密码，继续使用邮箱 OTP：%s", email)
        return _login_via_email_otp(
            session,
            email,
            otp_after_ts,
            email_source=email_source,
        )

    logger.info("[查活] 账号存在密码，优先走密码登录：%s", email)
    password_result = _password_verify(session, password)
    continue_url = _extract_continue_url(password_result)
    page = password_result.get("page") if isinstance(password_result, dict) else {}
    page = page if isinstance(page, dict) else {}
    page_type = str(page.get("type") or "")

    if "/mfa-challenge/" in continue_url or page_type == "mfa_challenge":
        factor_id = _extract_factor_id(password_result, continue_url)
        secret = _account_totp_secret(email)
        if not factor_id:
            raise RuntimeError(f"密码登录后进入 MFA 但未拿到 factor_id: {password_result}")
        if not secret:
            raise RuntimeError(f"密码登录后进入 MFA，但账号没有 totp_secret：{email}")
        logger.info("[查活] 已进入 MFA challenge，开始提交 TOTP：%s factor_id=%s", email, factor_id)
        _mfa_issue_challenge(session, factor_id)
        code = _account_totp_code(email)
        if not code:
            raise RuntimeError(f"无法生成 TOTP 验证码：{email}")
        mfa_result = _mfa_verify(session, factor_id, code)
        mfa_continue_url = _extract_continue_url(mfa_result) or continue_url
        if not mfa_continue_url:
            raise RuntimeError(f"MFA 验证成功但没有 continue_url: {mfa_result}")
        return _follow_continue_and_fetch(
            session,
            mfa_continue_url,
            referer=f"https://auth.openai.com/mfa-challenge/{factor_id}",
        )

    if "email-verification" in continue_url or page_type in {"email_verification", "email_otp_send"}:
        logger.info("[查活] 密码登录后仍进入邮箱 OTP，继续完成邮箱验证：%s", email)
        return _login_via_email_otp(
            session,
            email,
            otp_after_ts,
            email_source=email_source,
        )

    if continue_url:
        logger.info("[查活] 密码登录直接给出回调地址，继续完成回调：%s", email)
        return _follow_continue_and_fetch(session, continue_url, referer="https://auth.openai.com/log-in/password")

    raise RuntimeError(f"密码登录成功但没有可用 continue_url: {password_result}")


def log_path(email: str) -> Path:
    safe = str(email or "").replace("/", "_").replace("\\", "_").replace(":", "_")
    return _LOG_DIR / f"live-check-{safe}.log"


def is_checking(email: str) -> bool:
    key = str(email or "").strip().lower()
    with _RUNNING_LOCK:
        return key in _RUNNING


def _validate_with_retry(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    max_otp_attempts: int = 3,
    email_source: str | None = None,
) -> dict:
    current_otp = None
    last_exc: Exception | None = None
    for attempt in range(1, max_otp_attempts + 1):
        try:
            if current_otp is None:
                logger.info("[查活] 等待登录 OTP：%s（第 %s/%s 次）", email, attempt, max_otp_attempts)
                current_otp = wait_for_otp(
                    email,
                    after_ts=otp_after_ts,
                    email_source=email_source,
                )
            result = validate_email_otp(session, current_otp, sentinel_header=None, so_header=None)
            return result
        except EmailOtpInvalidError as exc:
            last_exc = exc
            if attempt >= max_otp_attempts:
                break
            logger.warning("[查活] OTP 无效/过期，重新发送后再取：%s", str(exc)[:180])
            send_email_otp(session)
            # 以“重新发送请求完成后”为新基准，避免刚刚失败的上一封旧码再次被 after 容忍窗口命中。
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
        except Exception as exc:
            # 提交 OTP 后的网络抖动（连接断开/超时/代理波动）：同一会话重发验证码再验证一次。
            if attempt >= max_otp_attempts or not _is_retryable_network_error(exc):
                raise
            last_exc = exc
            logger.warning("[查活] OTP 验证网络抖动，重新发送后再取（%s/%s）：%s", attempt, max_otp_attempts, str(exc)[:180])
            try:
                send_email_otp(session)
            except Exception:
                raise
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
    raise last_exc if last_exc else RuntimeError("OTP 验证失败")


def check_account_liveness(
    email: str,
    proxy: str | None = None,
    *,
    clear_log: bool = True,
    email_source: str | None = None,
    use_roxy_browser: bool = False,
    roxy_proxy: str | None = None,
) -> dict:
    """
    重新登录账号并刷新最新 accessToken。

    返回：
      {
        ok: bool,
        status: live/deactivated/failed,
        access_token: str?,
        session: dict?,
        checked_at: ISO,
        error: str?
      }
    """
    email = str(email or "").strip()
    if not email:
        raise ValueError("email 不能为空")

    checked_at = _now()
    key = email.lower()
    path = log_path(email)
    path.parent.mkdir(parents=True, exist_ok=True)
    if clear_log:
        path.write_text("", encoding="utf-8")

    fh: logging.FileHandler | None = None
    session: BrowserSession | None = None
    refreshed_proxy_used: str | None = None
    root_logger = logging.getLogger()
    thread_name = threading.current_thread().name
    with _RUNNING_LOCK:
        _RUNNING.add(key)
    try:
        fh = logging.FileHandler(str(path), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        fh.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(fh)

        logger.info("[查活] 日志文件：%s", path)
        logger.info("[查活] 开始重新登录：%s", email)
        existing_access_token = _stored_access_token(email)
        if existing_access_token:
            # 正常查活先验证已存的 AT。此前 TOTP/2FA 账号仍会被强制跑 reauth → 邮箱 OTP，
            # 一旦取码服务不同步就会大面积失败；AT 仍可调用 /me 已足以证明账号在线。
            logger.info("[查活] 流程：现有 AT /me 验证 →（失效时）登录态预热 → Reauth → OTP")
            session = BrowserSession(proxy=proxy, fingerprint_seed=f"account:{email.lower()}")
            logger.info(
                "[查活] 会话创建完成：proxy=%s device_id=%s（复用2FA稳定链路）",
                session.proxy or "直连/配置随机",
                session.device_id,
            )
            logger.info("[查活] 指纹摘要：%s", session.fingerprint_summary_text())
            token_identity = _check_stored_access_token(session, existing_access_token)
            if token_identity is not None:
                fp = _safe_fingerprint_for_account(session)
                return {
                    "ok": True,
                    "status": "live",
                    "checked_at": checked_at,
                    "access_token": existing_access_token.removeprefix("Bearer ").removeprefix("bearer "),
                    "session": {"user": token_identity},
                    "proxy_used": session.proxy or None,
                    "fingerprint": fp,
                    "fingerprint_text": _safe_fingerprint_text_for_account(session),
                }
            if use_roxy_browser:
                # HTTP BrowserSession 在过期 AT 的 reauth 链上容易被 403/CF 熔断；
                # 这里切到 RoxyBrowser Chromium，同一代理出口下完成 CSRF/signin/OTP/callback。
                logger.info("[查活] 现有 AT 验证未通过，切换 RoxyBrowser reauth 刷新过期 AT")
                session_info, roxy_meta = _login_via_roxy_browser_reauth(
                    email,
                    proxy=roxy_proxy if roxy_proxy is not None else proxy,
                    email_source=email_source,
                )
                refreshed_proxy_used = str((roxy_meta or {}).get("proxy_used") or "") or None
            else:
                _warm_authenticated_session(session, existing_access_token)
                human_delay("navigate")
                session_info = _login_via_reauth(session, email, time.time(), email_source=email_source)
        else:
            # 兼容没有本地 AT 或已开启 TOTP 的记录。providers 不是 signin 的
            # 前置依赖，备用链只执行 CSRF → Signin，避免在 providers 403 时提前终止。
            logger.info("[查活] 流程：CSRF → Signin → Authorize → 密码/邮箱 OTP → MFA(如有) → OAuth callback → Session/AT")
            session, authorize_url = _network_preflight_with_retry(email, proxy)

            otp_after_ts = time.time()
            final_url = follow_authorize(session, authorize_url)
            dead_code = detect_account_unusable_text(final_url)
            if dead_code:
                return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": dead_code}

            session_info = _login_via_password_or_otp(
                session,
                email,
                otp_after_ts,
                email_source=email_source,
            )
        access_token = str(session_info.get("accessToken") or "")
        if not access_token:
            raise RuntimeError("重新登录后未拿到 accessToken")

        user = session_info.get("user") or {}
        account = session_info.get("account") or {}
        logger.info("[查活] 正常：%s user_id=%s plan=%s", email, user.get("id"), account.get("planType"))
        fp = _safe_fingerprint_for_account(session)
        return {
            "ok": True,
            "status": "live",
            "checked_at": checked_at,
            "access_token": access_token,
            "session": session_info,
            "proxy_used": refreshed_proxy_used or (session.proxy if session is not None else None),
            "fingerprint": fp,
            "fingerprint_text": _safe_fingerprint_text_for_account(session),
        }
    except AccountUnusableError as exc:
        code = getattr(exc, "error_code", "") or detect_account_unusable_text(str(exc)) or "account_deactivated"
        logger.warning("[查活] 已废号：%s %s", email, code)
        return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code}
    except Exception as exc:
        code = detect_account_unusable_text(_exception_response_text(exc)) or detect_account_unusable_text(str(exc))
        if code:
            logger.warning("[查活] 已废号：%s %s", email, code)
            return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code}
        if _is_access_blocked_error(exc):
            status = _exception_status_code(exc)
            logger.warning("[查活] 访问受限：%s HTTP %s（账号状态未知）", email, status)
            return {
                "ok": False,
                "status": "blocked",
                "checked_at": checked_at,
                "error": f"HTTP {status}: provider access denied; account state is unknown",
            }
        if _is_permanent_pickup_error(exc):
            logger.warning("[查活] 隐藏邮箱/取码地址已失效：%s %s: %s", email, type(exc).__name__, str(exc)[:260])
            return {
                "ok": False,
                "status": "mail_deleted",
                "checked_at": checked_at,
                "error": f"隐藏邮箱已删除或取码密钥失效：{str(exc)[:420]}",
            }
        logger.warning("[查活] 失败：%s %s: %s", email, type(exc).__name__, str(exc)[:260])
        return {"ok": False, "status": "failed", "checked_at": checked_at, "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
    finally:
        try:
            logger.info("[查活] 结束：%s", email)
            if session is not None:
                try:
                    session.session.close()
                except Exception:
                    pass
            if fh is not None:
                root_logger.removeHandler(fh)
                fh.close()
        finally:
            with _RUNNING_LOCK:
                _RUNNING.discard(key)
