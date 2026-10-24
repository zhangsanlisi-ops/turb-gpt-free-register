"""Im-Run Browser Open API client.

The service exposes ``/start`` and ``/stop`` (not Roxy's ``/open`` and
``/close``).  Keep this adapter separate so the existing Roxy integration is
not affected by Im-Run API changes.
"""
from __future__ import annotations

import time
import random
import threading
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

import requests

from config import imrunbrowser as _cfg


_PROXY_ASSIGNMENT_LOCK = threading.RLock()
_PROXY_ENDPOINTS_USED: set[str] = set()


@dataclass
class ImRunOpenResult:
    profile_id: str
    raw: dict
    debugger_address: str | None = None
    webdriver_url: str | None = None
    ws_endpoint: str | None = None
    created_by_run: bool = False
    proxy_used: str = ""


@dataclass
class ImRunSession:
    connect_url: str
    api_key_present: bool
    proxy_country_code: str = ""
    profile_id: str = ""
    raw: dict | None = None
    proxy_used: str = ""


class ImRunBrowserClient:
    def __init__(self, base: str | None = None, key: str | None = None):
        self.base = (base or _cfg.IMRUN_API_BASE).strip().rstrip("/")
        self.key = (key if key is not None else _cfg.IMRUN_API_KEY).strip()
        self.http = requests.Session()
        self._last_selected_proxy = ""
        self.http.headers.update({"Accept": "application/json"})
        if self.key:
            self.http.headers["X-API-Key"] = self.key

    def request(self, method: str, path: str, **kwargs) -> dict:
        # 调用方在清理阶段可传更短 timeout；不能与默认 timeout 关键字重复传给 requests。
        timeout = kwargs.pop("timeout", max(5, int(_cfg.IMRUN_API_TIMEOUT)))
        response = self.http.request(
            method.upper(), f"{self.base}{path}",
            timeout=timeout, **kwargs,
        )
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, dict) else {"data": payload}

    def profiles(self) -> list[dict]:
        data = self.request("GET", "/profiles")
        return data.get("data", data) if isinstance(data.get("data", data), list) else []

    def create_profile(self, payload: dict) -> dict:
        return self.request("POST", "/profiles", json=payload)

    @staticmethod
    def _proxy_draft(proxy_url: str) -> dict:
        text = str(proxy_url or "").strip()
        if "://" not in text:
            parts = text.split(":")
            if len(parts) >= 4 and parts[1].isdigit():
                host, port, username = parts[0], parts[1], parts[2]
                password = ":".join(parts[3:])
                scheme = "socks5" if "1024proxy.io" in host.lower() else "http"
                return {
                    "type": scheme,
                    "host": host,
                    "port": int(port),
                    "username": username,
                    "password": password,
                }
        parsed = urlparse(text)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https", "socks5", "socks5h"} or not parsed.hostname or not parsed.port:
            raise ValueError("Im-Run 代理必须是 http(s)://user:pass@host:port、socks5://... 或 host:port:user:pass 格式")
        result = {"type": "socks5" if scheme == "socks5h" else scheme, "host": parsed.hostname, "port": parsed.port}
        if parsed.username:
            result["username"] = unquote(parsed.username)
        if parsed.password:
            result["password"] = unquote(parsed.password)
        return result

    def _profile_draft(self) -> dict:
        draft = {
            "name": f"{_cfg.IMRUN_PROFILE_NAME_PREFIX}-{int(time.time() * 1000)}-{random.randrange(0x10000):04x}",
            "browserKernel": "system-chrome",
            "startUrls": [str(_cfg.IMRUN_START_URL).strip()] if str(_cfg.IMRUN_START_URL).strip() else [],
            "tags": ["turb-gpt", "one-profile-per-account"],
        }
        self._last_selected_proxy = ""
        if bool(_cfg.IMRUN_CREATE_USE_PROXY_POOL):
            from config import proxy as proxy_cfg
            candidates = [str(item).strip() for item in (getattr(proxy_cfg, "PROXY_POOL", []) or []) if str(item).strip()]
            if not candidates:
                raise RuntimeError("IMRUN_CREATE_USE_PROXY_POOL=True，但「代理池」为空")
            # Profile 生命周期内固定一条代理；同批注册优先不复用端点。
            with _PROXY_ASSIGNMENT_LOCK:
                if bool(getattr(_cfg, "IMRUN_PROXY_NO_REUSE", True)):
                    available = [item for item in candidates if item not in _PROXY_ENDPOINTS_USED]
                    if not available:
                        _PROXY_ENDPOINTS_USED.clear()
                        available = candidates
                    selected_proxy = random.choice(available)
                    _PROXY_ENDPOINTS_USED.add(selected_proxy)
                else:
                    selected_proxy = random.choice(candidates)
            self._last_selected_proxy = selected_proxy
            draft["proxy"] = self._proxy_draft(selected_proxy)
        return draft

    @staticmethod
    def _debugger_address(payload: dict) -> str:
        value = str(payload.get("debug_url") or payload.get("debugUrl") or "").strip()
        if value:
            parsed = urlparse(value)
            return parsed.netloc or value.replace("http://", "").replace("https://", "")
        ws = str(payload.get("wsEndpoint") or "").strip()
        parsed = urlparse(ws)
        return parsed.netloc if parsed.netloc else ""

    def open_profile(self) -> ImRunOpenResult:
        one_per_account = bool(_cfg.IMRUN_ONE_PROFILE_PER_ACCOUNT)
        profile_id = "" if one_per_account else str(_cfg.IMRUN_PROFILE_ID or "").strip()
        created_by_run = False
        if not profile_id:
            if not one_per_account:
                profiles = self.profiles()
                if profiles:
                    profile_id = str(profiles[0].get("id") or "").strip()
            if not profile_id:
                created = self.create_profile(self._profile_draft())
                profile_id = str(created.get("id") or "").strip()
                created_by_run = True
        if not profile_id:
            raise RuntimeError("Im-Run 未找到可用 Profile，先在 Im-Run 创建环境或填写 IMRUN_PROFILE_ID")

        # Im-Run 将该参数交给 Chromium 启动器；False 保持可见窗口以便人工排查。
        payload = self.request(
            "POST", f"/profiles/{profile_id}/start",
            json={"headless": bool(getattr(_cfg, "IMRUN_HEADLESS", False))},
        )
        return ImRunOpenResult(
            profile_id=profile_id,
            raw=payload,
            debugger_address=self._debugger_address(payload),
            ws_endpoint=str(payload.get("wsEndpoint") or "") or None,
            created_by_run=created_by_run,
            proxy_used=str(getattr(self, "_last_selected_proxy", "") or ""),
        )

    def cleanup_profile(self, opened: ImRunOpenResult, *, timeout: int | None = None) -> None:
        """Stop profile and delete only the short-lived Profile created by this run."""
        if not opened or not opened.profile_id:
            return
        if bool(_cfg.IMRUN_KEEP_BROWSER_OPEN):
            return
        request_kwargs = {"timeout": max(3, int(timeout))} if timeout is not None else {}
        self.request("POST", f"/profiles/{opened.profile_id}/stop", **request_kwargs)
        if opened.created_by_run and bool(_cfg.IMRUN_DELETE_PROFILE_AFTER_RUN):
            self.request("DELETE", f"/profiles/{opened.profile_id}", **request_kwargs)

    def open_session(self) -> ImRunSession:
        """Return a Playwright-compatible local CDP session (no chromedriver)."""
        self._opened = self.open_profile()
        connect_url = str(self._opened.ws_endpoint or self._opened.debugger_address or "").strip()
        if connect_url and not connect_url.startswith(("ws://", "wss://", "http://", "https://")):
            connect_url = f"http://{connect_url}"
        if not connect_url:
            raise RuntimeError("Im-Run start 未返回 wsEndpoint/debug_url，无法连接 CDP")
        return ImRunSession(
            connect_url=connect_url,
            api_key_present=bool(self.key),
            profile_id=self._opened.profile_id,
            raw=self._opened.raw,
            proxy_used=self._opened.proxy_used,
        )

    def close_session(self, *, timeout: int | None = None) -> None:
        opened = getattr(self, "_opened", None)
        if opened is not None:
            self.cleanup_profile(opened, timeout=timeout)
            self._opened = None

    def close_session_async(self, *, timeout: int = 10) -> bool:
        """后台回收临时 Profile，绝不让注册任务卡在 Im-Run 的 stop/delete 请求上。"""
        opened = getattr(self, "_opened", None)
        self._opened = None
        if opened is None:
            return False

        def _cleanup() -> None:
            try:
                self.cleanup_profile(opened, timeout=timeout)
            except Exception:
                # 回收失败不影响已保存账号；下次启动可由 Im-Run 自行回收残留进程。
                pass

        threading.Thread(
            target=_cleanup,
            name=f"imrun-cleanup-{opened.profile_id[:8]}",
            daemon=True,
        ).start()
        return True
