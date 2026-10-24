# -*- coding: utf-8 -*-
"""ChatGPT 账号套餐/试用资格查询。"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import quote, urlparse

from core.session import BrowserSession

logger = logging.getLogger(__name__)

ACCOUNTS_CHECK_PATH = "/backend-api/accounts/check/v4-2023-04-27"
# RoxyBrowser 本地 API/临时 Profile 不适合并行创建；套餐队列可以并发
# 预检 HTTP，但进入浏览器兜底时必须串行。
_ROXY_PLAN_BROWSER_LOCK = threading.Lock()


def _normalize_proxy_url(proxy: str, default_scheme: str = "http") -> str:
    """Normalize proxy formats used by config/proxy.py into URL form."""
    text = str(proxy or "").strip()
    if not text:
        return ""
    if "://" in text:
        return text
    parts = text.split(":")
    if len(parts) >= 4 and parts[1].isdigit():
        host, port, username = parts[0], parts[1], parts[2]
        password = ":".join(parts[3:])
        return f"{default_scheme}://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
    if len(parts) == 2 and parts[1].isdigit():
        return f"{default_scheme}://{text}"
    return text


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def normalize_token(token: str) -> str:
    token = (token or "").strip().strip('"').strip("'")
    if token.lower().startswith("authorization:"):
        token = token.split(":", 1)[1].strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _mask_proxy(proxy: str) -> str:
    """返回可用于日志/API 结果的代理摘要，不泄露用户名和密码。"""
    value = _normalize_proxy_url(str(proxy or "").strip())
    if not value:
        return ""
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        scheme = f"{parsed.scheme}://" if parsed.scheme else ""
        auth = "***:***@" if parsed.username or parsed.password else ""
        return f"{scheme}{auth}{host}{port}" or "***"
    except Exception:
        return "***"




def _is_imrun_proxy_marker(proxy: str) -> bool:
    value = str(proxy or "").strip().lower()
    return value in {"imrun", "im-run", "imrunbrowser"} or value.startswith(("imrun:", "im-run:", "imrunbrowser:"))


def _local_proxy_status(proxy: str) -> tuple[bool, bool, str | None]:
    """检查回环代理端口；非本地代理不做预探测，避免额外网络请求。"""
    value = str(proxy or "").strip()
    if not value:
        return False, False, None
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        is_loopback = host.lower() == "localhost"
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            return False, True, None
        if not parsed.port:
            return True, False, "本地代理未配置端口"
        try:
            with socket.create_connection((host, parsed.port), timeout=0.5):
                return True, True, None
        except OSError as exc:
            return True, False, f"本地代理 {host}:{parsed.port} 未监听（{type(exc).__name__}）"
    except Exception as exc:
        return False, False, f"代理地址解析失败（{type(exc).__name__}）"


def resolve_plan_check_route(explicit_proxy: Optional[str] = None) -> dict:
    """解析套餐查询的实际网络路径。

    explicit_proxy 不是 None 时表示 API 调用方明确覆盖配置；空字符串代表直连。
    """
    if explicit_proxy is not None:
        raw_selected = str(explicit_proxy or "").strip()
        if _is_imrun_proxy_marker(raw_selected):
            return {
                "proxy": "",
                "proxy_mode": "roxy_profile",
                "network_route": "roxy_browser",
                "proxy_used": "RoxyBrowser（历史账号仅保存 imrun 标记，无法还原原 Im-Run 代理）",
                "proxy_fallback_reason": "账号历史记录为 imrun:*，已按要求改用本地 RoxyBrowser；该旧记录没有保存原始注册代理",
                "strict_proxy": False,
            }
        selected = _normalize_proxy_url(raw_selected)
        if selected:
            return {
                "proxy": selected,
                "proxy_mode": "roxy_profile",
                "network_route": "roxy_browser",
                "proxy_used": _mask_proxy(selected),
                "proxy_fallback_reason": "使用注册时保存的代理/IP 在本地 RoxyBrowser Profile 中查询",
                "strict_proxy": True,
            }
        return {
            "proxy": "",
            "proxy_mode": "direct",
            "network_route": "direct",
            "proxy_used": None,
            "proxy_fallback_reason": None,
            "strict_proxy": True,
        }

    from config import proxy as proxy_cfg

    mode = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY_MODE", "auto") or "auto").strip().lower()
    if mode not in {"auto", "proxy", "direct"}:
        raise ValueError(f"PLAN_CHECK_PROXY_MODE={mode!r} 无效，可选 auto / proxy / direct")
    if mode == "direct":
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct",
            "proxy_used": None,
            "proxy_fallback_reason": None,
        }

    selected = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY", "") or "").strip()
    if not selected:
        selected = str(proxy_cfg.pick_proxy() or "").strip()
    if not selected:
        if mode == "proxy":
            raise ValueError("套餐查询网络模式为 proxy，但未配置 PLAN_CHECK_PROXY 或 PROXY_POOL")
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct",
            "proxy_used": None,
            "proxy_fallback_reason": "未配置套餐查询代理或代理池",
        }

    is_local, available, reason = _local_proxy_status(selected)
    if mode == "auto" and is_local and not available:
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct_fallback",
            "proxy_used": _mask_proxy(selected),
            "proxy_fallback_reason": reason,
        }
    return {
        "proxy": _normalize_proxy_url(selected),
        "proxy_mode": "roxy_profile",
        "network_route": "roxy_browser",
        "proxy_used": _mask_proxy(selected),
        "proxy_fallback_reason": "使用配置的套餐查询代理/IP 在本地 RoxyBrowser Profile 中查询",
    }


def _maybe_start_plan_proxy_chain(route: dict) -> tuple[dict, object | None]:
    """为 1024proxy 这类需走本地上游的代理启动临时本地链式端口。"""
    selected = str((route or {}).get("proxy") or "").strip()
    if not selected:
        return route, None
    try:
        from config import roxybrowser as roxy_cfg
        from core.roxy_proxy_chain import looks_like_1024_proxy, start_proxy_chain

        if not bool(getattr(roxy_cfg, "ROXY_PROXY_CHAIN_ENABLED", False)):
            return route, None
        if not looks_like_1024_proxy(selected):
            return route, None
        upstream = str(getattr(roxy_cfg, "ROXY_PROXY_CHAIN_UPSTREAM", "http://127.0.0.1:7897") or "http://127.0.0.1:7897").strip()
        handle = start_proxy_chain(
            selected,
            upstream_proxy=upstream,
            base_port=int(getattr(roxy_cfg, "ROXY_PROXY_CHAIN_BASE_PORT", 18100) or 18100),
            max_ports=int(getattr(roxy_cfg, "ROXY_PROXY_CHAIN_MAX_PORTS", 300) or 300),
        )
        chained = dict(route)
        original_route = str(chained.get("network_route") or "")
        chained["proxy"] = handle.local_proxy
        if original_route == "roxy_browser":
            # 1024proxy 需要本地链式端口，但查询仍然必须走 RoxyBrowser，
            # 不能退回 curl/request，否则会再次出现 TLS/403/出口不一致问题。
            chained["proxy_mode"] = "roxy_profile"
            chained["network_route"] = "roxy_browser"
            chained["proxy_fallback_reason"] = "使用注册代理的本地链式端口在 RoxyBrowser Profile 中查询"
        else:
            chained["proxy_mode"] = "proxy_chain"
            chained["network_route"] = "proxy_chain"
            chained["proxy_fallback_reason"] = None
        chained["proxy_used"] = f"{_mask_proxy(selected)} via {handle.local_proxy}"
        return chained, handle
    except Exception as exc:
        raise RuntimeError(f"启动套餐查询代理链失败: {type(exc).__name__}: {str(exc)[:160]}") from exc


def decode_jwt_payload_unverified(token: str) -> dict:
    """仅本地解析 JWT payload，不校验签名。"""
    token = normalize_token(token)
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return {}


def token_claims(token: str) -> dict:
    payload = decode_jwt_payload_unverified(token)
    auth = payload.get("https://api.openai.com/auth") or {}
    profile = payload.get("https://api.openai.com/profile") or {}
    exp = payload.get("exp")
    exp_iso = None
    expired = None
    if isinstance(exp, (int, float)):
        exp_iso = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        expired = datetime.now(tz=timezone.utc).timestamp() >= float(exp)
    return {
        "payload": payload,
        "email": profile.get("email"),
        "user_name": profile.get("name"),
        "user_id": auth.get("chatgpt_user_id") or auth.get("user_id"),
        "account_id": auth.get("chatgpt_account_id"),
        "claim_plan_type": auth.get("chatgpt_plan_type"),
        "exp": exp,
        "token_expires_at": exp_iso,
        "token_expired": expired,
    }


def _common_headers(env: BrowserSession, token: str) -> dict[str, str]:
    headers = env._get_common_headers()
    headers.update({
        "accept": "*/*",
        "authorization": f"Bearer {normalize_token(token)}",
        "oai-device-id": env.device_id,
        "oai-language": env.navigator_language(),
        "referer": "https://chatgpt.com/",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-openai-target-path": ACCOUNTS_CHECK_PATH,
        "x-openai-target-route": ACCOUNTS_CHECK_PATH,
    })
    return headers


def parse_accounts_check(data: dict, *, token: str = "") -> dict:
    """从 accounts/check 响应提取套餐和 Plus 试用资格。"""
    claims = token_claims(token) if token else {}
    claim_account_id = claims.get("account_id")
    accounts = data.get("accounts") if isinstance(data, dict) else None
    if not isinstance(accounts, dict):
        raise ValueError("响应缺少 accounts 对象")

    item = None
    account_key = None
    if claim_account_id and isinstance(accounts.get(claim_account_id), dict):
        item = accounts.get(claim_account_id)
        account_key = claim_account_id
    elif isinstance(accounts.get("default"), dict):
        item = accounts.get("default")
        account = item.get("account") or {}
        account_key = account.get("account_id") or "default"
    else:
        for k, v in accounts.items():
            if k != "default" and isinstance(v, dict):
                item = v
                account_key = k
                break
    if not isinstance(item, dict):
        raise ValueError("未找到可解析的账号条目")

    account = item.get("account") or {}
    entitlement = item.get("entitlement") or {}
    last_sub = item.get("last_active_subscription") or {}
    eligible_promo_campaigns = item.get("eligible_promo_campaigns") or {}
    plus_campaign = eligible_promo_campaigns.get("plus") if isinstance(eligible_promo_campaigns, dict) else None
    plus_meta = (plus_campaign or {}).get("metadata") or {}
    discount = plus_meta.get("discount") or {}
    duration = plus_meta.get("duration") or {}
    campaign_id = str((plus_campaign or {}).get("id") or "").strip().lower()
    half_price_campaigns = {
        "plus-3-months-50-pct-off": 3,
        "plus-2-months-50-pct-off": 2,
        "plus-1-month-50-pct-off": 1,
    }
    percentage = discount.get("percentage")
    try:
        percentage_value = float(str(percentage).strip().rstrip("%")) if percentage is not None else None
    except (TypeError, ValueError):
        percentage_value = None
    # Known campaign IDs and equivalent 1/2/3-month offers with explicit
    # 50% monthly metadata all represent non-zero promotions, not free trials.
    id_months = half_price_campaigns.get(campaign_id)
    metadata_months = None
    if campaign_id.startswith("plus-") and percentage_value == 50.0 and str(duration.get("period") or "").lower() in {"month", "months", "monthly"}:
        try:
            value = int(duration.get("num_periods"))
            metadata_months = value if value in (1, 2, 3) else None
        except (TypeError, ValueError):
            pass
    half_price_months = id_months if id_months and percentage_value in (None, 50.0) else metadata_months

    plan_type = account.get("plan_type") or claims.get("claim_plan_type") or ""
    subscription_plan = entitlement.get("subscription_plan") or ""
    has_active_subscription = bool(entitlement.get("has_active_subscription"))
    is_free = str(plan_type).lower() == "free" or str(subscription_plan).lower() == "chatgptfreeplan"
    plus_half_price_eligible = bool(is_free and half_price_months)
    plus_trial_eligible = bool(is_free and plus_campaign and not plus_half_price_eligible)

    offers = ((item.get("eligible_offers") or {}).get("offers") or [])
    eligible_offer_ids = [o.get("id") for o in offers if isinstance(o, dict) and o.get("id")]

    result = {
        "ok": True,
        "checked_at": now_iso(),
        "account_id": account.get("account_id") or account_key or claim_account_id,
        "account_user_role": account.get("account_user_role"),
        "current_plan_type": plan_type,
        "subscription_plan": subscription_plan,
        "has_active_subscription": has_active_subscription,
        "is_active_subscription_gratis": bool(entitlement.get("is_active_subscription_gratis")),
        "expires_at": entitlement.get("expires_at"),
        "renews_at": entitlement.get("renews_at"),
        "cancels_at": entitlement.get("cancels_at"),
        "billing_period": entitlement.get("billing_period"),
        "billing_currency": entitlement.get("billing_currency"),
        "is_delinquent": bool(entitlement.get("is_delinquent")),
        "discount_type": (entitlement.get("discount") or {}).get("discount_type"),
        "discount_amount": (entitlement.get("discount") or {}).get("amount"),
        "discount_duration_num_periods": (entitlement.get("discount") or {}).get("duration_num_periods"),
        "discount_expires_at": (entitlement.get("discount") or {}).get("discount_expires_at"),
        "discount_cancellation_policy": (entitlement.get("discount") or {}).get("cancellation_policy"),
        "discount_promo_campaign_id": (entitlement.get("discount") or {}).get("promo_campaign_id"),
        "last_purchase_origin_platform": last_sub.get("purchase_origin_platform"),
        "last_will_renew": bool(last_sub.get("will_renew")),
        "plus_trial_eligible": plus_trial_eligible,
        "promo_status": "NON_ZERO_PROMO" if plus_half_price_eligible else None,
        "plus_half_price_eligible": plus_half_price_eligible,
        "plus_half_price_months": half_price_months if plus_half_price_eligible else None,
        "plus_half_price_campaign_id": campaign_id if plus_half_price_eligible else None,
        "plus_half_price_discount_percentage": 50 if plus_half_price_eligible else None,
        "plus_trial_campaign_id": (plus_campaign or {}).get("id") if plus_trial_eligible else None,
        "plus_trial_title": plus_meta.get("title") if plus_trial_eligible else None,
        "plus_trial_summary": plus_meta.get("summary") if plus_trial_eligible else None,
        "plus_trial_discount_percentage": discount.get("percentage") if plus_trial_eligible else None,
        "plus_trial_duration_num_periods": duration.get("num_periods") if plus_trial_eligible else None,
        "plus_trial_duration_period": duration.get("period") if plus_trial_eligible else None,
        "plus_trial_promotion_type_label": plus_meta.get("promotion_type_label") if plus_trial_eligible else None,
        "eligible_offer_ids": eligible_offer_ids,
        "features_count": len(item.get("features") or []),
        "can_access_with_session": bool(item.get("can_access_with_session")),
        "raw_account_plan_type": account.get("plan_type"),
    }
    result.update({k: v for k, v in claims.items() if k != "payload" and v is not None})
    return result


def _plan_check_settings(
    timeout: float | None,
    max_attempts: int | None,
    retry_delay: float | None,
) -> tuple[float, int, float]:
    from config import proxy as proxy_cfg

    timeout_value = timeout if timeout is not None else getattr(proxy_cfg, "PLAN_CHECK_TIMEOUT", 15.0)
    attempts_value = max_attempts if max_attempts is not None else getattr(proxy_cfg, "PLAN_CHECK_MAX_ATTEMPTS", 2)
    delay_value = retry_delay if retry_delay is not None else getattr(proxy_cfg, "PLAN_CHECK_RETRY_DELAY", 1.5)
    return (
        max(1.0, min(60.0, float(timeout_value or 15.0))),
        max(1, min(4, int(attempts_value or 1))),
        max(0.0, min(30.0, float(delay_value or 0.0))),
    )


def _roxy_plan_proxy_payload(proxy: str | None) -> dict:
    """Build Roxy create payload that uses exactly the supplied proxy route."""
    selected = str(proxy or "").strip()
    if not selected:
        return {}
    from core.roxybrowser_client import (
        _normalize_proxy_url as _roxy_normalize_proxy_url,
        _proxy_url_to_roxy_info,
    )

    normalized = _roxy_normalize_proxy_url(selected)
    return {
        "proxyInfo": _proxy_url_to_roxy_info(normalized),
        "proxy": normalized,
    }


def _check_account_plan_via_roxy_browser(token: str, timezone_offset_min: str, *, proxy: str | None = None) -> tuple[dict | None, dict]:
    """在本地 RoxyBrowser Chromium 内请求套餐接口。"""
    try:
        from core.roxybrowser_client import RoxyBrowserClient, _mask_proxy as _roxy_mask_proxy, _register_official_roxynet_proxy
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return None, {"enabled": True, "error": f"RoxyBrowser 依赖不可用: {type(exc).__name__}: {str(exc)[:160]}"}

    acquired = _ROXY_PLAN_BROWSER_LOCK.acquire(timeout=240)
    if not acquired:
        return None, {"enabled": True, "error": "RoxyBrowser 套餐浏览器繁忙，等待超时"}

    client = RoxyBrowserClient()
    opened = None
    browser = None
    roxynet_handle = None
    try:
        proxy_for_roxy = str(proxy or "").strip()
        if proxy_for_roxy:
            roxynet = _register_official_roxynet_proxy(proxy_for_roxy)
            if roxynet is not None:
                proxy_for_roxy, roxynet_handle = roxynet
                logger.info(
                    "[Plan] 套餐查询启用官方 roxynet 映射：source=%s local=%s",
                    _roxy_mask_proxy(proxy or ""),
                    _roxy_mask_proxy(proxy_for_roxy),
                )
        payload = _roxy_plan_proxy_payload(proxy_for_roxy)
        opened = client.open_profile(payload=payload or None)
        connect_target = str(opened.ws_endpoint or opened.debugger_address or "").strip()
        if connect_target and not connect_target.startswith(("ws://", "wss://", "http://", "https://")):
            connect_target = f"http://{connect_target}"
        if not connect_target:
            return None, {"enabled": True, "error": "RoxyBrowser open 未返回 CDP 调试地址"}

        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(connect_target)
            context = browser.contexts[0] if browser.contexts else browser.new_context()
            page = context.new_page()
            page.set_default_timeout(30000)
            target_url = f"https://chatgpt.com{ACCOUNTS_CHECK_PATH}?timezone_offset_min={quote(str(timezone_offset_min or '-'))}"
            page.set_extra_http_headers({
                "accept": "application/json, text/plain, */*",
                "authorization": f"Bearer {token}",
                "cache-control": "no-cache",
                "pragma": "no-cache",
                "oai-device-id": str(uuid.uuid4()),
                "oai-language": "en-US",
                "x-openai-target-path": ACCOUNTS_CHECK_PATH,
                "x-openai-target-route": ACCOUNTS_CHECK_PATH,
            })
            # 直接导航到 accounts/check JSON 接口，避免先加载 chatgpt.com 首页导致
            # domcontentloaded 超时或用户中止请求；仍然使用 RoxyBrowser/Chromium 网络栈和代理出口。
            try:
                resp = page.goto(target_url, wait_until="commit", timeout=30000)
            except Exception as first_exc:
                # 兼容较旧 Playwright 不支持 wait_until=commit 的情况；JSON 文档通常很快触发 domcontentloaded。
                logger.debug("RoxyBrowser 套餐 direct goto(commit) 失败，改用 domcontentloaded: %s", first_exc)
                resp = page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
            status = int(resp.status if resp is not None else 0)
            try:
                text = resp.text() if resp is not None else page.locator("body").inner_text(timeout=5000)
            except Exception:
                text = page.locator("body").inner_text(timeout=5000)
            try:
                data = json.loads(text) if str(text or "").strip().startswith(("{", "[")) else None
            except Exception:
                data = None
            result = {"status": status, "data": data, "preview": str(text or "")[:300]}
            meta = {
                "enabled": True,
                "http_status": status or None,
                "profile_id": opened.profile_id,
                "proxy_used": _roxy_mask_proxy(proxy or "") if proxy else None,
                "roxy_proxy": _roxy_mask_proxy(proxy_for_roxy) if proxy_for_roxy else None,
                "preview": (result or {}).get("preview"),
            }
            if 200 <= status < 300 and isinstance(data, dict):
                return data, meta
            return None, {**meta, "error": f"RoxyBrowser 套餐接口未返回 JSON/成功状态: HTTP {status or '-'}"}
    except Exception as exc:
        return None, {"enabled": True, "error": f"RoxyBrowser 浏览器查询失败: {type(exc).__name__}: {str(exc)[:220]}"}
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
                pass
        if roxynet_handle is not None:
            try:
                roxynet_handle.stop()
                logger.info(
                    "[Plan] 已释放套餐查询 roxynet 映射：local=%s",
                    getattr(roxynet_handle, "local_proxy", "-"),
                )
            except Exception:
                pass
        _ROXY_PLAN_BROWSER_LOCK.release()


def _should_try_roxy_browser_fallback_error(exc: Exception) -> bool:
    """curl_cffi 经过 SOCKS/HTTP 代理发生 TLS 协议错配时，改用 Chromium 网络栈。"""
    text = f"{type(exc).__name__}: {exc}".lower()
    return any(item in text for item in (
        "sslerror", "tls connect", "wrong_version_number", "curl: (35)",
        "proxyerror", "connection reset", "connection refused", "timeout",
        "timed out", "curl: (28)", "connection timed out",
    ))


def _retryable_plan_error(http_status: int | None) -> bool:
    if http_status is None:
        return True
    # chatgpt.com occasionally returns a Cloudflare/edge HTML challenge as 403
    # for otherwise-valid access tokens.  Treat it as transient so the normal
    # retry loop can re-attempt after the RoxyBrowser Chromium fallback has failed.
    # Auth failures are still reported as 401 by this endpoint.
    return http_status in {403, 408, 409, 425, 429} or http_status >= 500


def _retry_wait_seconds(resp: Any, base_delay: float, attempt: int) -> float:
    try:
        retry_after = (getattr(resp, "headers", {}) or {}).get("retry-after")
        if retry_after is not None:
            return max(0.0, min(30.0, float(retry_after)))
    except (TypeError, ValueError):
        pass
    return max(0.0, min(30.0, base_delay * attempt))


def check_account_plan(
    token: str,
    *,
    proxy: Optional[str] = None,
    timezone_offset_min: str = "-",
    timeout: float | None = None,
    max_attempts: int | None = None,
    retry_delay: float | None = None,
) -> dict:
    token = normalize_token(token)
    if not token:
        return {"ok": False, "checked_at": now_iso(), "error": "token 为空"}
    claims = token_claims(token)
    if claims.get("token_expired") is True:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": "AT已过期/失效，请手动查活刷新",
            "needs_live_check": True,
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    proxy_chain_handle = None
    try:
        route = resolve_plan_check_route(proxy)
        route, proxy_chain_handle = _maybe_start_plan_proxy_chain(route)
    except Exception as exc:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"套餐查询网络配置错误: {exc}",
            **{k: v for k, v in claims.items() if k != "payload"},
        }
    route_meta = {k: v for k, v in route.items() if k not in {"proxy", "strict_proxy"}}
    url = f"https://chatgpt.com{ACCOUNTS_CHECK_PATH}?timezone_offset_min={quote(str(timezone_offset_min))}"
    try:
        timeout_seconds, attempts, base_delay = _plan_check_settings(timeout, max_attempts, retry_delay)
    except Exception as exc:
        if proxy_chain_handle is not None:
            try:
                proxy_chain_handle.stop()
            except Exception:
                pass
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"套餐查询重试配置错误: {exc}",
            "retryable": False,
            **route_meta,
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    if route.get("network_route") == "roxy_browser":
        try:
            browser_meta = {}
            attempt = 0
            for attempt in range(1, attempts + 1):
                browser_data, browser_meta = _check_account_plan_via_roxy_browser(token, timezone_offset_min, proxy=route.get("proxy"))
                if isinstance(browser_data, dict):
                    parsed = parse_accounts_check(browser_data, token=token)
                    parsed.update({
                        "http_status": int(browser_meta.get("http_status") or 200),
                        "attempt_count": attempt,
                        "max_attempts": attempts,
                        "request_timeout": timeout_seconds,
                        "retryable": False,
                        "transport": "roxy_browser",
                        **route_meta,
                    })
                    return parsed
                http_status = browser_meta.get("http_status")
                if attempt >= attempts or not _retryable_plan_error(http_status):
                    break
                time.sleep(min(30.0, base_delay * attempt))
            http_status = browser_meta.get("http_status")
            is_auth_expired = int(http_status or 0) == 401
            return {
                "ok": False,
                "checked_at": now_iso(),
                "http_status": http_status,
                "error": "AT已过期/失效，请手动查活刷新" if is_auth_expired else (browser_meta.get("error") or "RoxyBrowser 浏览器套餐查询失败"),
                "retryable": not is_auth_expired and _retryable_plan_error(http_status),
                "attempt_count": attempt,
                "max_attempts": attempts,
                "request_timeout": timeout_seconds,
                "token_expired": True if is_auth_expired else claims.get("token_expired"),
                "needs_live_check": True if is_auth_expired else False,
                "transport": "roxy_browser",
                **route_meta,
                **{k: v for k, v in claims.items() if k != "payload"},
            }
        finally:
            if proxy_chain_handle is not None:
                try:
                    proxy_chain_handle.stop()
                except Exception:
                    pass

    last_result: dict | None = None
    account_seed = f"account:{(claims.get('email') or claims.get('account_id') or normalize_token(token)[:32]).lower()}"
    try:
        for attempt in range(1, attempts + 1):
            env = None
            resp = None
            try:
                # 套餐查询只需要稳定的请求头，不需要额外访问 IP 地理信息接口。
                env = BrowserSession(proxy=route["proxy"], detect_exit_geo=False, fingerprint_seed=account_seed)
                resp = env.session.get(
                    url,
                    headers=_common_headers(env, token),
                    allow_redirects=False,
                    timeout=timeout_seconds,
                )
                response_text = resp.text or ""
                http_status = int(resp.status_code)
                if not (200 <= http_status < 300):
                    # 普通 HTTP 被拦时，用本地 RoxyBrowser Chromium 按同一代理路线重试一次。
                    browser_meta: dict[str, Any] = {}
                    if http_status == 403:
                        browser_data, browser_meta = _check_account_plan_via_roxy_browser(token, timezone_offset_min, proxy=route.get("proxy"))
                        if isinstance(browser_data, dict):
                            parsed = parse_accounts_check(browser_data, token=token)
                            parsed.update({
                                "http_status": int(browser_meta.get("http_status") or 200),
                                "attempt_count": attempt,
                                "max_attempts": attempts,
                                "request_timeout": timeout_seconds,
                                "retryable": False,
                                "transport": "roxy_browser",
                                "network_route": "roxy_browser",
                                "proxy_mode": "roxy_profile",
                                "proxy_used": route_meta.get("proxy_used"),
                                "proxy_fallback_reason": "普通 HTTP 返回 403，已由 RoxyBrowser Chromium 使用同一代理路线成功重试",
                            })
                            return parsed
                        logger.warning("套餐普通 HTTP 返回 403，RoxyBrowser 浏览器兜底未成功: %s", browser_meta.get("error") or browser_meta.get("http_status"))
                    is_auth_expired = http_status == 401
                    fallback_reason = None
                    if http_status == 403:
                        fallback_reason = browser_meta.get("error") or (
                            f"RoxyBrowser HTTP {browser_meta.get('http_status')}" if browser_meta.get("http_status") else None
                        )
                    last_result = {
                        "ok": False,
                        "checked_at": now_iso(),
                        "http_status": http_status,
                        "error": "AT已过期/失效，请手动查活刷新" if is_auth_expired else (
                            f"HTTP {http_status}，RoxyBrowser 兜底未成功: {fallback_reason}" if fallback_reason else f"HTTP {http_status}"
                        ),
                        "response_preview": response_text[:500],
                        "retryable": _retryable_plan_error(http_status),
                        "token_expired": True if is_auth_expired else claims.get("token_expired"),
                        "needs_live_check": True if is_auth_expired else False,
                    }
                else:
                    try:
                        data: Any = resp.json()
                    except Exception:
                        data = json.loads(response_text) if response_text.strip().startswith(("{", "[")) else None
                    if not isinstance(data, dict):
                        last_result = {
                            "ok": False,
                            "checked_at": now_iso(),
                            "http_status": http_status,
                            "error": "响应不是 JSON 对象",
                            "response_preview": response_text[:500],
                            "retryable": True,
                        }
                    else:
                        parsed = parse_accounts_check(data, token=token)
                        parsed["http_status"] = http_status
                        parsed["attempt_count"] = attempt
                        parsed["max_attempts"] = attempts
                        parsed["request_timeout"] = timeout_seconds
                        parsed["retryable"] = False
                        parsed.update(route_meta)
                        return parsed
            except Exception as exc:
                # curl_cffi + 代理可能在 TLS 协议协商阶段报 WRONG_VERSION_NUMBER；
                # 这不是账号状态，用 RoxyBrowser Chromium 的原生网络栈再试一次。
                if _should_try_roxy_browser_fallback_error(exc):
                    browser_data, browser_meta = _check_account_plan_via_roxy_browser(token, timezone_offset_min, proxy=route.get("proxy"))
                    if isinstance(browser_data, dict):
                        parsed = parse_accounts_check(browser_data, token=token)
                        parsed.update({
                            "http_status": int(browser_meta.get("http_status") or 200),
                            "attempt_count": attempt,
                            "max_attempts": attempts,
                            "request_timeout": timeout_seconds,
                            "retryable": False,
                            "transport": "roxy_browser",
                            "network_route": "roxy_browser",
                            "proxy_mode": "roxy_profile",
                            "proxy_used": route_meta.get("proxy_used"),
                            "proxy_fallback_reason": "普通 HTTP TLS/SSL 异常，已由 RoxyBrowser Chromium 使用同一代理路线成功重试",
                        })
                        return parsed
                    logger.warning("套餐 HTTP TLS 异常，RoxyBrowser 浏览器兜底未成功: %s", browser_meta.get("error") or browser_meta.get("http_status"))
                logger.debug("套餐查询失败: %s: %s", type(exc).__name__, exc, exc_info=True)
                last_result = {
                    "ok": False,
                    "checked_at": now_iso(),
                    "http_status": int(resp.status_code) if resp is not None and getattr(resp, "status_code", None) else None,
                    "error": (
                        f"注册代理查询失败（已按注册代理/IP 路线查询，没有切换到其它出口）：{type(exc).__name__}: {exc}"
                        if route.get("strict_proxy") else f"{type(exc).__name__}: {exc}"
                    ),
                    "retryable": True,
                }
            finally:
                if env is not None:
                    try:
                        env.session.close()
                    except Exception:
                        pass

            last_result = last_result or {"ok": False, "checked_at": now_iso(), "error": "未知错误", "retryable": True}
            last_result.update({
                "attempt_count": attempt,
                "max_attempts": attempts,
                "request_timeout": timeout_seconds,
                **route_meta,
                **{k: v for k, v in claims.items() if k != "payload"},
            })
            if not last_result.get("retryable") or attempt >= attempts:
                return last_result

            wait_seconds = _retry_wait_seconds(resp, base_delay, attempt)
            logger.warning(
                "套餐查询临时失败，第 %s/%s 次，%.1fs 后重试: %s",
                attempt,
                attempts,
                wait_seconds,
                last_result.get("error"),
            )
            if wait_seconds > 0:
                time.sleep(wait_seconds)
    finally:
        if proxy_chain_handle is not None:
            try:
                proxy_chain_handle.stop()
            except Exception:
                pass

    return last_result or {
        "ok": False,
        "checked_at": now_iso(),
        "http_status": None,
        "error": "套餐查询未执行",
        "retryable": False,
        **route_meta,
        **{k: v for k, v in claims.items() if k != "payload"},
    }
