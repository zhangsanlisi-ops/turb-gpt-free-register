# -*- coding: utf-8 -*-
"""账号查活后台队列：协议 BrowserSession 指纹环境 + 独立日志。"""
from __future__ import annotations

import logging
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlparse

from core import db
from core.account_liveness import check_account_liveness, log_path
from core.chatgpt_plan import _mask_proxy, _maybe_start_plan_proxy_chain, resolve_plan_check_route

logger = logging.getLogger(__name__)

_WORKERS = 3
_QUEUE_LIMIT = 500
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="live-check")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_RUNNING: set[int] = set()
_LOCK = threading.Lock()


def _normalize_proxy_url(proxy: str, default_scheme: str = "socks5") -> str:
    """把 host:port:user:pass 代理格式规范成 URL。"""
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


def _is_local_proxy(proxy: str) -> bool:
    """判断代理是否是本地回环出口；查活不再使用固定 127.0.0.1:7897。"""
    value = _normalize_proxy_url(proxy)
    if not value:
        return False
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = (parsed.hostname or "").lower()
        return host in {"127.0.0.1", "localhost", "::1"}
    except Exception:
        return False


def _pick_live_proxy(exclude: set[str] | None = None) -> str:
    """为查活从代理池挑选非本地出口，排除已失败出口。"""
    from config import proxy as proxy_cfg

    excluded = {str(item or "").strip() for item in (exclude or set()) if str(item or "").strip()}
    pool = []
    explicit = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY", "") or "").strip()
    if explicit:
        pool.append(explicit)
    pool.extend(str(item or "").strip() for item in (getattr(proxy_cfg, "PROXY_POOL", []) or []))
    candidates = []
    for item in pool:
        normalized = _normalize_proxy_url(item)
        if not normalized or normalized in excluded or _is_local_proxy(normalized):
            continue
        candidates.append(normalized)
    if not candidates:
        return ""
    return random.choice(candidates)


def _live_route(proxy: str) -> dict:
    """构造查活使用的网络路由日志。"""
    if not proxy:
        return {
            "proxy": "",
            "proxy_mode": "direct",
            "network_route": "direct",
            "proxy_used": None,
            "proxy_fallback_reason": "未找到非本地查活代理，临时直连",
        }
    return {
        "proxy": proxy,
        "proxy_mode": "roxy_profile",
        "network_route": "roxy_browser",
        "proxy_used": _mask_proxy(proxy),
        "proxy_fallback_reason": "查活专用：从代理池随机选择非本地出口",
    }


def _prepare_live_route(proxy: str) -> tuple[dict, object | None]:
    """构造查活路由；1024proxy 自动套本地链式端口。"""
    route = _live_route(proxy)
    try:
        return _maybe_start_plan_proxy_chain(route)
    except Exception as exc:
        logger.warning("[查活] 启动查活代理链失败，将按原代理继续: %s", exc)
        route = dict(route)
        route["proxy_fallback_reason"] = (
            f"{route.get('proxy_fallback_reason') or '查活代理'}；代理链启动失败，按原代理继续"
        )
        return route, None


def is_checking(email: str) -> bool:
    acc = db.get_account_by_email(email)
    if not acc:
        return False
    return str(acc.get("live_check_status") or "") in {"queued", "running"}


def _append_log(email: str, line: str, *, clear: bool = False) -> None:
    p = log_path(email)
    p.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    mode = "w" if clear else "a"
    with p.open(mode, encoding="utf-8") as f:
        f.write(f"{stamp} [INFO] {line}\n")


def _run_live_check(*, account_id: int, email: str, proxy: str | None, trigger: str) -> dict:
    chain_handles: list[object] = []
    try:
        with _LOCK:
            _RUNNING.add(int(account_id))
        if not db.mark_account_live_check_running(account_id):
            _append_log(email, "[查活] 账号已删除或查活状态已被重置，取消执行")
            return {"ok": False, "status": "failed", "error": "账号已删除或查活状态已被重置"}
        selected_for_live = _normalize_proxy_url(proxy or "") if proxy else _pick_live_proxy()
        route, chain_handle = _prepare_live_route(selected_for_live)
        if chain_handle is not None:
            chain_handles.append(chain_handle)
        selected_proxy = route.get("proxy")
        # 查活必须沿用账号注册时记录的邮箱来源。不能只调用
        # resolve_email_source(email)：Remail 等临时邮箱的上下文只在领取进程
        # 内存中存在，服务重启后按当前 EMAIL_SOURCE 推断会把来源判错。
        try:
            account = db.get_account(account_id) or {}
        except Exception:
            account = {}
        email_source = str(account.get("email_source") or "").strip() or None
        if email_source:
            _append_log(email, f"[查活] 使用注册时保存的邮箱来源：{email_source}")
        _append_log(
            email,
            "[查活] 开始后台执行 "
            f"trigger={trigger} network_route={route.get('network_route')} "
            f"proxy_mode={route.get('proxy_mode')} proxy_used={route.get('proxy_used') or '-'} "
            f"fallback_reason={route.get('proxy_fallback_reason') or '-'}"
        )
        result = check_account_liveness(
            email,
            proxy=selected_proxy,
            clear_log=False,
            email_source=email_source,
            use_roxy_browser=(route.get("network_route") == "roxy_browser"),
            roxy_proxy=selected_proxy,
        )
        # 认证链早期 403/429 不能证明账号失效。将其标为访问受限并停止，
        # 不要改走其它网络路由反复尝试，否则只会放大服务端访问限制。
        err_text = str(result.get("error") or "")
        # 单个代理偶发 TLS/连接异常时，先换池内另一条出口；这类错误并非账号或
        # accessToken 状态，不能直接判定账号失效。
        if (
            not result.get("ok")
            and result.get("status") == "failed"
            and selected_proxy
            and any(hint in err_text.lower() for hint in (
                "sslerror", "tls connect", "wrong_version_number",
                "connectionerror", "could not connect", "failed to connect", "connection was reset",
                "err_connection_closed", "connection closed abruptly", "ssl_error_syscall",
            ))
        ):
            retry_source_proxy = _pick_live_proxy({str(selected_for_live)})
            if retry_source_proxy:
                _append_log(email, "[查活] 代理连接异常，换代理池出口重试一次")
                retry_route, retry_handle = _prepare_live_route(retry_source_proxy)
                if retry_handle is not None:
                    chain_handles.append(retry_handle)
                result = check_account_liveness(
                    email,
                    proxy=retry_route.get("proxy"),
                    clear_log=False,
                    email_source=email_source,
                    use_roxy_browser=(retry_route.get("network_route") == "roxy_browser"),
                    roxy_proxy=retry_route.get("proxy"),
                )
                selected_for_live = retry_source_proxy
                selected_proxy = retry_route.get("proxy")
                err_text = str(result.get("error") or "")
        if (
            not result.get("ok")
            and result.get("status") in {"failed", "blocked"}
            and selected_proxy
            and "403" in err_text
        ):
            retry_source_proxy = _pick_live_proxy({str(selected_for_live)})
            if retry_source_proxy:
                retry_route, retry_handle = _prepare_live_route(retry_source_proxy)
                if retry_handle is not None:
                    chain_handles.append(retry_handle)
                _append_log(email, f"[查活] 当前出口 HTTP 403，换非本地代理重试一次：{_mask_proxy(retry_source_proxy)}")
                result = check_account_liveness(
                    email,
                    proxy=retry_route.get("proxy"),
                    clear_log=False,
                    email_source=email_source,
                    use_roxy_browser=(retry_route.get("network_route") == "roxy_browser"),
                    roxy_proxy=retry_route.get("proxy"),
                )
                selected_for_live = retry_source_proxy
                selected_proxy = retry_route.get("proxy")
                err_text = str(result.get("error") or "")
        if (
            not result.get("ok")
            and result.get("status") == "failed"
            and any(code in err_text for code in ("403", "429"))
        ):
            result = {
                **result,
                "status": "blocked",
                "error": "provider access denied; account state is unknown",
            }
            _append_log(email, "[查活] 服务端拒绝访问；已标记为访问受限，未重试其它网络路由")
        db.update_account_liveness(account_id, result)
        if result.get("ok"):
            _append_log(email, "[查活] 完成：账号正常，已刷新最新 AT/accessToken")
        elif result.get("status") == "deactivated":
            _append_log(email, f"[查活] 完成：账号已废 {result.get('error') or ''}")
        elif result.get("status") == "blocked":
            _append_log(email, f"[查活] 完成：访问受限，账号状态未知 {result.get('error') or ''}")
        elif result.get("status") == "mail_deleted":
            _append_log(email, f"[查活] 完成：隐藏邮箱已删/取码失效 {result.get('error') or ''}")
        else:
            _append_log(email, f"[查活] 完成：失败 {result.get('error') or ''}")
        return result
    except Exception as exc:
        result = {
            "ok": False,
            "status": "failed",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"{type(exc).__name__}: {str(exc)[:500]}",
        }
        try:
            db.update_account_liveness(account_id, result)
        except Exception:
            logger.exception("[查活] 写入异常状态失败: account_id=%s", account_id)
        logger.exception("[查活] 后台异常: %s", email)
        try:
            _append_log(email, f"[查活] 后台异常：{result['error']}")
        except Exception:
            pass
        return result
    finally:
        for handle in reversed(chain_handles):
            try:
                handle.stop()
            except Exception:
                logger.debug("[查活] 停止查活代理链失败", exc_info=True)
        with _LOCK:
            _RUNNING.discard(int(account_id))
        _QUEUE_SLOTS.release()


def enqueue_account_live_check(*, account_id: int, email: str, trigger: str = "manual", proxy: str | None = None) -> dict:
    account_id = int(account_id)
    email = str(email or "").strip()
    if not email:
        return {"accepted": False, "busy": False, "error": "email 为空"}
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "queue_full": True, "error": "查活队列已满，请稍后重试"}
    if not db.claim_account_live_check(acc_id=account_id, trigger=trigger):
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在查活"}

    _append_log(email, f"[查活] 已入队 account_id={account_id} trigger={trigger}", clear=True)
    try:
        _EXECUTOR.submit(
            _run_live_check,
            account_id=account_id,
            email=email,
            proxy=proxy,
            trigger=str(trigger or "manual"),
        )
    except Exception as exc:
        _QUEUE_SLOTS.release()
        result = {
            "ok": False,
            "status": "failed",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"查活入队失败: {type(exc).__name__}: {str(exc)[:160]}",
        }
        db.update_account_liveness(account_id, result)
        _append_log(email, result["error"])
        return {"accepted": False, "busy": False, "error": result["error"]}

    return {
        "accepted": True,
        "busy": False,
        "account_id": account_id,
        "email": email,
        "status": "queued",
        "trigger": str(trigger or "manual"),
    }


def queue_settings() -> dict:
    return {"workers": _WORKERS, "queue_limit": _QUEUE_LIMIT}
