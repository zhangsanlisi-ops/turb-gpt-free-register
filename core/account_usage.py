# -*- coding: utf-8 -*-
"""Read ChatGPT/Codex quota windows with an account's existing access token."""
from __future__ import annotations

from datetime import datetime
import os
import socket
from urllib.parse import urlparse

import requests


USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"


def _fallback_proxy() -> str:
    """Use the app's local upstream when direct access is blocked."""
    explicit = str(os.getenv("ACCOUNT_USAGE_PROXY") or "").strip()
    if explicit:
        return explicit
    try:
        from config import roxybrowser
        candidate = str(getattr(roxybrowser, "ROXY_PROXY_CHAIN_UPSTREAM", "") or "").strip()
        parsed = urlparse(candidate)
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or not parsed.port:
            return ""
        with socket.create_connection((parsed.hostname, parsed.port), timeout=0.3):
            return candidate
    except (OSError, ValueError, ImportError):
        pass
    return ""


def _window(value: object) -> dict:
    data = value if isinstance(value, dict) else {}
    return {
        "used_percent": data.get("used_percent"),
        "limit_window_seconds": data.get("limit_window_seconds"),
        "reset_at": data.get("reset_at"),
    }


def fetch_account_usage(access_token: str, *, expected_email: str = "") -> dict:
    """Return only quota fields; never expose the AT or upstream identity data."""
    token = str(access_token or "").strip().removeprefix("Bearer ").strip()
    checked_at = datetime.now().isoformat(timespec="seconds")
    if not token:
        return {"ok": False, "checked_at": checked_at, "error": "账号没有 access_token"}

    request_args = {
        "headers": {"Authorization": f"Bearer {token}", "Accept": "application/json"},
        "timeout": (3, 12),
        "allow_redirects": False,
    }
    try:
        response = requests.get(USAGE_URL, **request_args)
    except requests.RequestException as exc:
        proxy = _fallback_proxy()
        if not proxy:
            return {"ok": False, "checked_at": checked_at, "error": f"网络错误：{type(exc).__name__}"}
        try:
            response = requests.get(
                USAGE_URL, proxies={"http": proxy, "https": proxy}, **request_args
            )
        except requests.RequestException as proxy_exc:
            return {"ok": False, "checked_at": checked_at, "error": f"网络错误：{type(proxy_exc).__name__}"}

    status = response.status_code
    if status != 200:
        reason = "AT 无效或无权限" if status in (401, 403) else "额度接口请求失败"
        return {"ok": False, "checked_at": checked_at, "http_status": status, "error": f"{reason}（HTTP {status}）"}
    try:
        data = response.json()
    except ValueError:
        return {"ok": False, "checked_at": checked_at, "http_status": status, "error": "额度接口未返回 JSON"}
    if not isinstance(data, dict) or not isinstance(data.get("rate_limit"), dict):
        return {"ok": False, "checked_at": checked_at, "http_status": status, "error": "额度接口返回结构异常"}
    returned_email = str(data.get("email") or "").strip()
    if expected_email and returned_email and returned_email.casefold() != expected_email.strip().casefold():
        return {"ok": False, "checked_at": checked_at, "http_status": status, "error": "AT 归属邮箱与该账号不一致"}

    limits = data["rate_limit"]
    return {
        "ok": True,
        "checked_at": checked_at,
        "http_status": status,
        "plan_type": data.get("plan_type"),
        "allowed": limits.get("allowed"),
        "limit_reached": limits.get("limit_reached"),
        "primary_window": _window(limits.get("primary_window")),
        "secondary_window": _window(limits.get("secondary_window")),
    }
