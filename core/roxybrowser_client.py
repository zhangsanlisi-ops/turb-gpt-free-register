# -*- coding: utf-8 -*-
"""RoxyBrowser 本地 API 客户端。"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, unquote, urljoin, urlparse

import requests

from config import roxybrowser as _cfg

logger = logging.getLogger(__name__)

_PROXY_RESERVE_LOCK = threading.RLock()
_RESERVED_PROXY_KEYS: set[str] = set()


@dataclass
class RoxyOpenResult:
    profile_id: str
    raw: dict
    debugger_address: str | None = None
    webdriver_url: str | None = None
    ws_endpoint: str | None = None
    created_by_run: bool = False
    proxy_chain_handle: object | None = None
    proxy_used: str | None = None


@dataclass
class RoxyNetProxyHandle:
    token: str
    local_proxy: str
    original_proxy: str
    control_port: int

    def stop(self) -> None:
        try:
            requests.get(
                f"http://127.0.0.1:{int(self.control_port)}/del_proxy",
                params={"id": self.token},
                timeout=5,
            )
        except Exception:
            pass


def _strip_slashes(value: str) -> str:
    return str(value or "").strip().strip("/")


def _join_url(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _normalize_proxy_url(proxy_url: str, default_scheme: str = "http") -> str:
    """Normalize proxy formats accepted by the WebUI.

    Supported inputs:
      - http://user:pass@host:port
      - socks5://user:pass@host:port
      - host:port:user:pass   (common proxy-list export format; default is caller-defined)
      - host:port             (default is caller-defined)
    """
    text = str(proxy_url or "").strip()
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


def _random_roxynet_token() -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "codex" + "".join(random.choice(alphabet) for _ in range(10))


def _tcp_port_listening(port: int, host: str = "127.0.0.1", timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def _roxynet_log_dirs() -> list[Path]:
    candidates: list[Path] = []
    # 常见安装位置；RoxyBrowser 新版本会把 roxynet 端口写到这里。
    candidates.append(Path(r"D:\rb浏览器\RoxyBrowser\logs\roxynet"))
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.append(Path(appdata) / "RoxyBrowser" / "logs" / "roxynet")
    localappdata = os.environ.get("LOCALAPPDATA")
    if localappdata:
        candidates.append(Path(localappdata) / "RoxyBrowser" / "logs" / "roxynet")
    return candidates


def _detect_roxynet_ports_from_logs() -> tuple[int | None, int | None]:
    """Return (control_port, socks_port) from latest official Roxy roxynet log."""
    log_files: list[Path] = []
    for directory in _roxynet_log_dirs():
        try:
            if directory.is_dir():
                log_files.extend(directory.glob("run_*.log"))
        except Exception:
            continue
    if not log_files:
        return None, None
    log_files.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    # roxynet 可以持续运行数天；启动端口只写在启动当天日志的开头。
    # 不能只看最近几天的日志尾部，否则长驻进程会被误判为未启动。
    for path in log_files[:30]:
        try:
            with path.open("rb") as stream:
                head = stream.read(256_000)
                stream.seek(0, 2)
                size = stream.tell()
                if size > len(head):
                    stream.seek(max(0, size - 256_000))
                    tail = stream.read()
                else:
                    tail = b""
            text = (head + b"\n" + tail).decode("utf-8", "ignore")
        except Exception:
            continue
        socks_matches: list[str] = []
        for line in text.splitlines():
            if "[mixed]" in line and "listen on" in line:
                nums = re.findall(r"\d+", line)
                if nums:
                    socks_matches.append(nums[-1])
        control_matches = re.findall(r"api server:Listening on\s+(\d+)\s+port", text)
        socks_port = int(socks_matches[-1]) if socks_matches else None
        control_port = int(control_matches[-1]) if control_matches else None
        if control_port and socks_port and _tcp_port_listening(control_port) and _tcp_port_listening(socks_port):
            return control_port, socks_port
    return None, None




def _windows_process_image(pid: int) -> str:
    """Read an executable name without tasklist, which can be access-denied."""
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.QueryFullProcessImageNameW.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
        )
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return ""
        try:
            path = ctypes.create_unicode_buffer(32768)
            length = wintypes.DWORD(len(path))
            if kernel32.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(length)):
                return path.value.rsplit("\\", 1)[-1].lower()
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        pass
    return ""


def _detect_roxynet_ports_from_netstat() -> tuple[int | None, int | None]:
    """Detect current roxynet dynamic ports from Windows netstat.

    Some RoxyBrowser builds do not create logs/roxynet/run_*.log, but roxynet.exe
    still listens on two random high ports: one HTTP control port (/set_proxy) and
    one SOCKS port.  Probe only ports owned by roxynet.exe.
    """
    if os.name != "nt":
        return None, None
    try:
        out = subprocess.check_output(["netstat", "-ano", "-p", "TCP"], text=True, errors="ignore", timeout=5)
    except Exception:
        return None, None
    by_pid: dict[int, list[int]] = {}
    for line in out.splitlines():
        if "LISTEN" not in line.upper():
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[1]
        try:
            pid = int(parts[-1])
            port = int(local.rsplit(":", 1)[-1].strip("[]"))
        except Exception:
            continue
        if 1024 <= port <= 65535:
            by_pid.setdefault(pid, []).append(port)
    for pid, ports in by_pid.items():
        if _windows_process_image(pid) != "roxynet.exe":
            continue
        control_port = None
        for port in sorted(set(ports)):
            try:
                # Invalid GET identifies the control API without changing proxy state.
                resp = requests.get(f"http://127.0.0.1:{port}/set_proxy", timeout=0.8)
                body = (resp.text or "").lower()
                if resp.status_code < 500 and ("proxy format" in body or "success" in body):
                    control_port = port
                    break
            except Exception:
                continue
        if not control_port:
            continue
        proxy_ports = [p0 for p0 in sorted(set(ports)) if p0 != control_port and _tcp_port_listening(p0, timeout=0.2)]
        if proxy_ports:
            return control_port, proxy_ports[0]
    return None, None


def _roxybrowser_exe_candidates() -> list[Path]:
    candidates = [
        Path(r"D:\rb浏览器\RoxyBrowser\RoxyBrowser.exe"),
    ]
    localappdata = os.environ.get("LOCALAPPDATA")
    if localappdata:
        candidates.extend([
            Path(localappdata) / "Programs" / "RoxyBrowser" / "RoxyBrowser.exe",
            Path(localappdata) / "RoxyBrowser" / "RoxyBrowser.exe",
        ])
    return candidates


def _start_roxybrowser_for_roxynet() -> bool:
    for exe in _roxybrowser_exe_candidates():
        try:
            if not exe.exists():
                continue
            creationflags = 0
            if os.name == "nt":
                creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            subprocess.Popen(
                [str(exe)],
                cwd=str(exe.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            logger.info("[Roxy] 已启动 RoxyBrowser 以拉起 roxynet：%s", exe)
            return True
        except Exception as exc:
            logger.warning("[Roxy] 启动 RoxyBrowser 失败：%s error=%s", exe, exc)
    return False


def _resolve_roxynet_ports() -> tuple[int, int]:
    """Resolve official roxynet control/socks ports.

    RoxyBrowser 旧版本常用固定 50276/50274；新版本会动态分配端口并写入
    logs/roxynet/run_*.log。注册前必须跟随真实端口，否则 /set_proxy 会 10061。
    """
    configured_control = int(getattr(_cfg, "ROXY_ROXYNET_HTTP_PORT", 50276) or 50276)
    configured_proxy = int(getattr(_cfg, "ROXY_ROXYNET_PROXY_PORT", 50274) or 50274)
    if _tcp_port_listening(configured_control) and _tcp_port_listening(configured_proxy):
        return configured_control, configured_proxy

    def detected_if_alive() -> tuple[int | None, int | None]:
        control, proxy = _detect_roxynet_ports_from_logs()
        if control and proxy and _tcp_port_listening(control) and _tcp_port_listening(proxy):
            return control, proxy
        control, proxy = _detect_roxynet_ports_from_netstat()
        if control and proxy and _tcp_port_listening(control) and _tcp_port_listening(proxy):
            return control, proxy
        return None, None

    control, proxy = detected_if_alive()
    if control and proxy:
        logger.info("[Roxy] 自动识别 roxynet 动态端口：control=%s socks=%s", control, proxy)
        return control, proxy

    _start_roxybrowser_for_roxynet()
    deadline = time.time() + 35
    while time.time() < deadline:
        if _tcp_port_listening(configured_control) and _tcp_port_listening(configured_proxy):
            return configured_control, configured_proxy
        control, proxy = detected_if_alive()
        if control and proxy:
            logger.info("[Roxy] RoxyBrowser 已拉起 roxynet：control=%s socks=%s", control, proxy)
            return control, proxy
        time.sleep(1)

    raise RuntimeError(
        "官方 Roxy roxynet 未启动或端口不可用。请打开 RoxyBrowser，确认 roxynet 控制端口已监听；"
        f"配置端口 control={configured_control}, socks={configured_proxy}，"
        f"日志检测端口={_detect_roxynet_ports_from_logs()}，netstat检测端口={_detect_roxynet_ports_from_netstat()}"
    )


def _roxy_pool_default_scheme() -> str:
    scheme = str(getattr(_cfg, "ROXY_PROXY_POOL_DEFAULT_SCHEME", "socks5") or "socks5").strip().lower()
    if scheme == "socks5h":
        scheme = "socks5"
    return scheme if scheme in ("http", "https", "socks5") else "socks5"


def _proxy_reuse_key(proxy_url: str) -> str:
    text = _normalize_proxy_url(proxy_url, default_scheme=_roxy_pool_default_scheme())
    parsed = urlparse(text)
    scheme = (parsed.scheme or "").lower()
    if scheme == "socks5h":
        scheme = "socks5"
    host = (parsed.hostname or "").lower()
    port = parsed.port or ""
    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    return f"{scheme}://{user}:{password}@{host}:{port}" if (user or password) else f"{scheme}://{host}:{port}"


def _historical_proxy_reuse_keys() -> set[str]:
    try:
        from core import db

        keys: set[str] = set()
        for row in db.list_accounts(limit=5000):
            value = str(row.get("proxy_used") or "").strip()
            if value:
                keys.add(_proxy_reuse_key(value))
        return keys
    except Exception:
        return set()


def _reserve_proxy_candidates(candidates: list[str]) -> list[str]:
    if not bool(getattr(_cfg, "ROXY_PROXY_POOL_NO_REUSE", True)):
        return candidates
    with _PROXY_RESERVE_LOCK:
        used = _historical_proxy_reuse_keys() | set(_RESERVED_PROXY_KEYS)
        fresh = [p for p in candidates if _proxy_reuse_key(p) not in used]
        if fresh:
            logger.info("[Roxy] 代理池去重：候选=%s 可用新代理=%s 已用/预留=%s", len(candidates), len(fresh), len(used))
            return fresh
        logger.warning("[Roxy] 代理池去重后无新代理，回退使用全池：候选=%s 已用/预留=%s", len(candidates), len(used))
        return candidates


def _mark_proxy_reserved(proxy_url: str) -> None:
    if not bool(getattr(_cfg, "ROXY_PROXY_POOL_NO_REUSE", True)):
        return
    with _PROXY_RESERVE_LOCK:
        _RESERVED_PROXY_KEYS.add(_proxy_reuse_key(proxy_url))


def _register_official_roxynet_proxy(proxy_url: str) -> tuple[str, RoxyNetProxyHandle] | None:
    """Register an external proxy in official Roxy roxynet and return local proxy URL.

    The official Roxy UI tests/uses residential proxy by registering the external
    proxy with roxynet first, then pointing the browser to a local authenticated
    SOCKS5 endpoint.  Direct RoxyChrome -> external 1024 proxy fails on this host.
    """
    if not bool(getattr(_cfg, "ROXY_USE_OFFICIAL_ROXYNET_PROXY", False)):
        return None
    normalized = _normalize_proxy_url(proxy_url, default_scheme=_roxy_pool_default_scheme())
    parsed = urlparse(normalized)
    scheme = (parsed.scheme or "").lower()
    if scheme == "socks5h":
        scheme = "socks5"
    if scheme not in ("http", "https", "socks5"):
        return None
    if not parsed.hostname or not parsed.port:
        return None
    # Only use roxynet for authenticated external proxies. Local proxies such as
    # 127.0.0.1:7897 should stay as-is.
    if not (parsed.username or parsed.password):
        return None
    if parsed.hostname in ("127.0.0.1", "localhost", "::1"):
        return None
    token = _random_roxynet_token()
    control_port, proxy_port = _resolve_roxynet_ports()
    payload = {
        token: {
            "addr": f"{parsed.hostname}:{int(parsed.port)}",
            "user_name": unquote(parsed.username or ""),
            "password": unquote(parsed.password or ""),
            "protocal": "socks5" if scheme == "socks5" else "http",
            "v2ray_tunnel_enabled": False,
        }
    }
    resp = requests.post(f"http://127.0.0.1:{control_port}/set_proxy", json=payload, timeout=10)
    if resp.status_code >= 400:
        raise RuntimeError(f"roxynet set_proxy failed: HTTP {resp.status_code}: {resp.text[:200]}")
    local_proxy = f"socks5://{quote(token, safe='')}:{quote(token, safe='')}@127.0.0.1:{proxy_port}"
    logger.info(
        "[Roxy] 已注册官方 roxynet 代理映射：source=%s local=socks5://***:***@127.0.0.1:%s token=%s",
        _mask_proxy(normalized),
        proxy_port,
        token,
    )
    return local_proxy, RoxyNetProxyHandle(
        token=token,
        local_proxy=local_proxy,
        original_proxy=normalized,
        control_port=control_port,
    )

def _mask_proxy(proxy_url: str) -> str:
    text = _normalize_proxy_url(proxy_url, default_scheme=_roxy_pool_default_scheme())
    parsed = urlparse(text)
    if parsed.username or parsed.password:
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://***:***@{host}{port}"
    return text


def _probe_http_connect_proxy(
    proxy_url: str,
    *,
    target_host: str = "chatgpt.com",
    target_port: int = 443,
    timeout: float = 8.0,
) -> tuple[bool, str]:
    """Preflight an HTTP CONNECT proxy before assigning it to RoxyChrome."""
    try:
        parsed = urlparse(_normalize_proxy_url(proxy_url))
        if (parsed.scheme or "").lower() not in ("http", "https"):
            return True, "skip_non_http_proxy"
        if not parsed.hostname or not parsed.port:
            return False, "missing_host_port"
        with socket.create_connection((parsed.hostname, int(parsed.port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            req = (
                f"CONNECT {target_host}:{int(target_port)} HTTP/1.1\r\n"
                f"Host: {target_host}:{int(target_port)}\r\n"
                "Proxy-Connection: Keep-Alive\r\n"
                "\r\n"
            ).encode("latin1")
            sock.sendall(req)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 4096:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        first = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
        ok = " 200 " in f" {first} " or first.endswith(" 200")
        return ok, first or "<empty_response>"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {str(exc)[:180]}"




def _maybe_start_proxy_chain(proxy_url: str):
    """Start a local Roxy-compatible proxy chain when configured/needed.

    Returns (proxy_url_for_roxy, handle). handle must be stopped on cleanup.
    """
    original = str(proxy_url or "").strip()
    if not original or not bool(getattr(_cfg, "ROXY_PROXY_CHAIN_ENABLED", False)):
        return original, None
    try:
        from core.roxy_proxy_chain import looks_like_1024_proxy, start_proxy_chain

        only_1024 = bool(getattr(_cfg, "ROXY_PROXY_CHAIN_ONLY_1024", True))
        if only_1024 and not looks_like_1024_proxy(original):
            return original, None
        upstream = str(getattr(_cfg, "ROXY_PROXY_CHAIN_UPSTREAM", "http://127.0.0.1:7897") or "http://127.0.0.1:7897").strip()
        handle = start_proxy_chain(
            original,
            upstream_proxy=upstream,
            base_port=int(getattr(_cfg, "ROXY_PROXY_CHAIN_BASE_PORT", 18100) or 18100),
            max_ports=int(getattr(_cfg, "ROXY_PROXY_CHAIN_MAX_PORTS", 300) or 300),
        )
        if bool(getattr(_cfg, "ROXY_PROXY_CHAIN_PREFLIGHT", True)):
            ok, detail = _probe_http_connect_proxy(handle.local_proxy)
            if not ok:
                try:
                    handle.stop()
                except Exception:
                    pass
                if bool(getattr(_cfg, "ROXY_PROXY_CHAIN_FALLBACK_TO_UPSTREAM", True)) and upstream:
                    upstream_ok, upstream_detail = _probe_http_connect_proxy(upstream)
                    if upstream_ok:
                        logger.warning(
                            "[Roxy] 本地链式代理预检失败，改用本地上游代理：source=%s local=%s detail=%s fallback=%s",
                            _mask_proxy(original),
                            handle.local_proxy,
                            detail,
                            _mask_proxy(upstream),
                        )
                        return upstream, None
                    logger.warning(
                        "[Roxy] 本地链式代理和上游代理预检均失败：source=%s local=%s detail=%s upstream=%s upstream_detail=%s",
                        _mask_proxy(original),
                        handle.local_proxy,
                        detail,
                        _mask_proxy(upstream),
                        upstream_detail,
                    )
                raise RuntimeError(f"Roxy proxy chain preflight failed: {handle.local_proxy} -> chatgpt.com:443: {detail}")
        logger.info(
            "[Roxy] 代理已转换为本地链式端口：source=%s local=%s upstream=%s",
            _mask_proxy(original),
            handle.local_proxy,
            upstream,
        )
        return handle.local_proxy, handle
    except Exception:
        logger.exception("[Roxy] 启动本地链式代理失败：source=%s", _mask_proxy(original))
        raise

def _proxy_url_to_roxy_info(proxy_url: str) -> dict:
    """
    Convert a proxy URL from config/proxy.py into Roxy /browser/create proxyInfo.

    Supports:
      http://user:pass@host:port
      https://user:pass@host:port
      socks5://user:pass@host:port
      socks5h://user:pass@host:port
      host:port:user:pass  -> normalized to http://user:pass@host:port
    """
    text = _normalize_proxy_url(proxy_url, default_scheme=_roxy_pool_default_scheme())
    if not text:
        raise ValueError("代理为空")
    parsed = urlparse(text)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https", "socks5", "socks5h"):
        raise ValueError(f"Roxy 暂不支持该代理协议: {scheme or '-'}")
    if not parsed.hostname or not parsed.port:
        raise ValueError(f"代理格式缺少 host/port: {_mask_proxy(text)}")

    protocol = {
        "http": "HTTP",
        "https": "HTTPS",
        "socks5": "SOCKS5",
        "socks5h": "SOCKS5",
    }[scheme]
    info = {
        "moduleId": 0,
        "proxyMethod": "custom",
        "proxyCategory": protocol,
        "ipType": "IPV4",
        "protocol": protocol,
        "host": parsed.hostname,
        "port": str(parsed.port),
    }
    if parsed.username:
        info["proxyUserName"] = unquote(parsed.username)
    if parsed.password:
        info["proxyPassword"] = unquote(parsed.password)
    check_channel = str(getattr(_cfg, "ROXY_PROXY_CHECK_CHANNEL", "") or "").strip()
    if check_channel:
        info["checkChannel"] = check_channel
    return info
def _dig(payload: dict, *keys: str):
    cur = payload
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _first(payload: dict, paths: list[tuple[str, ...]]) -> str:
    for path in paths:
        value = _dig(payload, *path)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _workspace_id_value() -> str | int:
    raw = str(getattr(_cfg, "ROXY_WORKSPACE_ID", "") or "").strip()
    if not raw:
        return ""
    return int(raw) if raw.isdigit() else raw


def _project_id_value() -> str | int:
    raw = str(getattr(_cfg, "ROXY_PROJECT_ID", "") or "").strip()
    if not raw:
        return ""
    return int(raw) if raw.isdigit() else raw


def _apply_data_saver_open_args(params: dict) -> dict:
    """在 Roxy 启动参数中尽早关闭图片加载，覆盖无扩展名图片 URL。

    Network.setBlockedURLs 只能按 URL 后缀拦截，而 Roxy 浏览器在 Selenium 连接
    前就已经启动；使用 Chromium 开关可以让图片在首个页面请求前就被禁用。该开关
    只在用户明确开启省流量模式且包含 image 类型时追加。
    """
    try:
        from config import browser as _browser_cfg

        if not bool(getattr(_browser_cfg, "BROWSER_DATA_SAVER_MODE", False)):
            return params
        raw_types = getattr(_browser_cfg, "BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES", [])
        if isinstance(raw_types, str):
            types = {item.strip().lower() for item in raw_types.replace(",", "\n").splitlines() if item.strip()}
        else:
            types = {str(item or "").strip().lower() for item in (raw_types or []) if str(item or "").strip()}
        current = params.get("args")
        if isinstance(current, (list, tuple)):
            args = list(current)
        elif current:
            args = [str(current)]
        else:
            args = []
        # 这些开关只关闭浏览器后台/统计/同步类网络，不影响页面主流程。
        safe_switches = [
            "--disable-background-networking",
            "--disable-sync",
            "--disable-component-update",
            "--metrics-recording-only",
            "--disable-features=OptimizationHints,MediaRouter,AutofillServerCommunication,Translate",
        ]
        if "image" in types or "images" in types or "img" in types:
            safe_switches.append("--blink-settings=imagesEnabled=false")
        for switch in safe_switches:
            if switch not in args:
                args.append(switch)
        params["args"] = args
    except Exception as exc:
        logger.debug("[Roxy] 添加省流量图片启动参数失败，继续使用原参数：%s", exc)
    return params


def _random_roxy_os() -> str:
    raw = str(getattr(_cfg, "ROXY_RANDOM_OS_CHOICES", "Windows,macOS") or "Windows,macOS")
    choices = [
        x.strip()
        for part in raw.replace("\n", ",").replace(";", ",").split(",")
        for x in [part]
        if x.strip()
    ]
    valid = {"Windows", "macOS", "Linux", "IOS", "Android"}
    choices = [x for x in choices if x in valid]
    if not choices:
        choices = ["Windows", "macOS"]
    return random.choice(choices)


def _random_roxy_profile_name() -> str:
    prefix = str(getattr(_cfg, "ROXY_PROFILE_NAME_PREFIX", "rb") or "rb").strip() or "rb"
    # Roxy 环境名每次创建都不同：前缀 + 毫秒时间戳 + 随机 4 位十六进制。
    return f"{prefix}-{int(time.time() * 1000)}-{random.randrange(0x10000):04x}"


class RoxyBrowserClient:
    def __init__(self, api_base: str | None = None, token: str | None = None):
        self.api_base = (api_base or _cfg.ROXY_API_BASE).strip()
        self.token = (token if token is not None else _cfg.ROXY_API_TOKEN).strip()
        self._proxy_chain_by_profile: dict[str, object] = {}
        self._proxy_used_by_profile: dict[str, str] = {}
        self.http = requests.Session()
        if self.token:
            # 官方文档要求所有接口请求头必须加 token。这里同时兼容 token / Authorization。
            self.http.headers.update({
                "token": self.token,
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            })

    @staticmethod
    def _is_retryable_error(exc: Exception) -> bool:
        text = str(exc or "").lower()
        return (
            "timeout" in text
            or "timed out" in text
            or "connection" in text
            or "temporarily" in text
            or "http 500" in text
            or "http 502" in text
            or "http 503" in text
            or "http 504" in text
            or "http 429" in text
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
        timeout: float | int | None = None,
    ) -> dict:
        url = _join_url(self.api_base, path)
        method_u = method.upper()
        # create 超时后服务端可能已创建环境，直接重试可能产生孤儿环境；默认不重试 create。
        # 但 TCP connection-refused 是请求尚未到达 Roxy 的明确证据，此时允许按普通
        # transient 策略重试，可覆盖 Roxy 本地 API 刚启动/刚重启的短窗口。
        is_create = str(path or "").rstrip("/").endswith("/create") or "browser/create" in str(path or "")
        # 循环上限仍取配置次数；create 的非 connection-refused 错误会在 except
        # 分支的 allowed_attempts=1 立即抛出，因而不会产生重复创建。
        max_attempts = max(1, int(getattr(_cfg, "ROXY_API_RETRIES", 3) or 3))
        base_delay = max(0.5, float(getattr(_cfg, "ROXY_API_RETRY_DELAY", 2) or 2))
        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                logger.debug(
                    "[Roxy] %s %s params=%s body=%s attempt=%s/%s",
                    method, url, params, json_body, attempt, max_attempts,
                )
                request_timeout = (
                    max(1.0, float(timeout))
                    if timeout is not None
                    else max(5, int(getattr(_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90))
                )
                resp = self.http.request(
                    method_u,
                    url,
                    params=params or None,
                    json=json_body if json_body is not None else None,
                    timeout=request_timeout,
                )
                text = resp.text or ""
                try:
                    payload = resp.json()
                except Exception:
                    payload = {"raw": text}
                if not (200 <= resp.status_code < 300):
                    raise RuntimeError(f"Roxy API 请求失败 {method_u} {path} HTTP {resp.status_code}: {text[:500]}")
                if isinstance(payload, dict):
                    code = payload.get("code")
                    ok = payload.get("ok")
                    success = payload.get("success")
                    if code not in (None, 0, 200, "0", "200") and ok is not True and success is not True:
                        msg = payload.get("msg") or payload.get("message") or payload.get("error") or json.dumps(payload, ensure_ascii=False)[:500]
                        raise RuntimeError(f"Roxy API 返回失败 {method_u} {path}: {msg}")
                if attempt > 1:
                    logger.info("[Roxy] API 重试成功：%s %s attempt=%s/%s", method_u, path, attempt, max_attempts)
                return payload if isinstance(payload, dict) else {"data": payload}
            except Exception as exc:
                last_exc = exc
                retryable = self._is_retryable_error(exc)
                retry_create_after_refused = is_create and isinstance(exc, requests.exceptions.ConnectionError)
                allowed_attempts = (
                    max(1, int(getattr(_cfg, "ROXY_API_RETRIES", 3) or 3))
                    if retry_create_after_refused
                    else max_attempts
                )
                if attempt >= allowed_attempts or not retryable:
                    raise
                delay = base_delay * attempt
                logger.warning(
                    "[Roxy] API 请求失败，将在 %.1fs 后重试：%s %s attempt=%s/%s%s error=%s",
                    delay, method_u, path, attempt, allowed_attempts,
                    " (create connection refused)" if retry_create_after_refused else "", exc,
                )
                time.sleep(delay)
        raise last_exc or RuntimeError(f"Roxy API 请求失败 {method_u} {path}")

    def try_request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
        timeout: float | int | None = None,
    ) -> tuple[bool, dict | str]:
        """宽松请求：用于探测不同 Roxy 版本接口，失败不抛出。"""
        try:
            return True, self.request(method, path, params=params, json_body=json_body, timeout=timeout)
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _profile_rows(payload: dict) -> list[dict]:
        """兼容不同 Roxy 版本的 Profile 列表响应。"""
        if not isinstance(payload, dict):
            return []
        data = payload.get("data")
        candidates = [data, payload]
        rows: list[dict] = []
        for item in candidates:
            if isinstance(item, dict):
                for key in ("rows", "list", "items"):
                    value = item.get(key)
                    if isinstance(value, list):
                        rows.extend(x for x in value if isinstance(x, dict))
            elif isinstance(item, list):
                rows.extend(x for x in item if isinstance(x, dict))
        return rows

    def _find_profile_by_window_name(self, workspace_id: str | int, window_name: str) -> str:
        """创建超时后按本次唯一窗口名确认服务端是否其实已完成创建。"""
        expected = str(window_name or "").strip()
        if not expected or not workspace_id:
            return ""
        # list_v2 是当前 Roxy API；list 保留给旧版本兼容。
        for path in ("/browser/list_v2", "/browser/list"):
            ok, payload = self.try_request(
                "GET",
                path,
                params={"workspaceId": workspace_id, "page_index": 1, "page_size": 100},
            )
            if not ok or not isinstance(payload, dict):
                continue
            for row in self._profile_rows(payload):
                name = str(row.get("windowName") or row.get("name") or "").strip()
                if name != expected:
                    continue
                profile_id = _first(row, [("dirId",), ("id",), ("dir_id",), ("profileId",), ("profile_id",)])
                if profile_id:
                    return str(profile_id)
        return ""

    @staticmethod
    def _extract_workspace_items(payload: dict) -> list[dict]:
        """解析 /browser/workspace：团队 rows + project_details 项目列表；兼容递归兜底。"""
        out = []

        # 官方结构：data.rows[].id/workspaceName/project_details[].projectId/projectName
        rows = None
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, dict):
                rows = data.get("rows") or data.get("list") or data.get("records")
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                wid = row.get("id") or row.get("workspaceId") or row.get("workspace_id")
                wname = row.get("workspaceName") or row.get("workspace_name") or row.get("name") or str(wid or "")
                projects = row.get("project_details") or row.get("projectDetails") or row.get("projects") or []
                if isinstance(projects, list) and projects:
                    for proj in projects:
                        if not isinstance(proj, dict):
                            continue
                        pid = proj.get("projectId") or proj.get("project_id") or proj.get("id")
                        pname = proj.get("projectName") or proj.get("project_name") or proj.get("name") or str(pid or "")
                        if wid:
                            out.append({
                                "id": str(wid),
                                "name": str(wname),
                                "projectId": str(pid or ""),
                                "projectName": str(pname or ""),
                                "label": f"{wname} / {pname} ({wid}/{pid})" if pid else f"{wname} ({wid})",
                                "raw": {"workspace": row, "project": proj},
                            })
                elif wid:
                    out.append({
                        "id": str(wid),
                        "name": str(wname),
                        "projectId": "",
                        "projectName": "",
                        "label": f"{wname} ({wid})",
                        "raw": row,
                    })

        if out:
            return out

        # 兜底：递归抽 workspace/team/company 结构。
        def pick_id_name(item: dict) -> tuple[str, str]:
            wid = _first(item, [
                ("workspaceId",), ("workspace_id",), ("workspaceID",),
                ("teamId",), ("team_id",), ("teamID",),
                ("companyId",), ("company_id",), ("orgId",), ("org_id",),
                ("id",), ("value",), ("key",),
            ])
            name = _first(item, [
                ("workspaceName",), ("workspace_name",),
                ("teamName",), ("team_name",),
                ("companyName",), ("company_name",),
                ("orgName",), ("org_name",),
                ("name",), ("label",), ("title",), ("remark",),
            ])
            return wid, name

        def looks_like_workspace(item: dict) -> bool:
            keys = {str(k).lower() for k in item.keys()}
            joined = " ".join(keys)
            return any(x in joined for x in ("workspace", "team", "company", "org")) or ("id" in keys and "name" in keys)

        def walk(node):
            if isinstance(node, dict):
                wid, name = pick_id_name(node)
                if wid and looks_like_workspace(node):
                    out.append({"id": wid, "name": name or wid, "projectId": "", "projectName": "", "label": f"{name or wid} ({wid})", "raw": node})
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(payload)
        dedup = {}
        for item in out:
            raw_keys = {str(k).lower() for k in (item.get("raw") or {}).keys()}
            if "dirid" in raw_keys and not any(k in raw_keys for k in ("workspaceid", "teamid", "companyid")):
                continue
            key = f"{item.get('id')}::{item.get('projectId','')}"
            dedup[key] = item
        return list(dedup.values())

    def list_workspaces(self) -> dict:
        """
        获取 Roxy 团队/工作区列表。
        Roxy 不同版本路径可能有差异，因此先试配置路径，再试常见路径。
        """
        configured = str(getattr(_cfg, "ROXY_WORKSPACE_LIST_PATH", "") or "").strip()
        method = str(getattr(_cfg, "ROXY_WORKSPACE_LIST_METHOD", "GET") or "GET").upper()
        candidates = []
        if configured:
            candidates.append((method, configured))
        candidates.extend([
            ("GET", "/browser/workspace"),
            ("POST", "/browser/workspace"),
            ("GET", "/workspace/list"),
            ("POST", "/workspace/list"),
            ("GET", "/workspace"),
            ("POST", "/workspace"),
            ("GET", "/team/list"),
            ("POST", "/team/list"),
            ("GET", "/team"),
            ("POST", "/team"),
            ("GET", "/workspaces"),
            ("GET", "/teams"),
            ("GET", "/user/workspace/list"),
            ("POST", "/user/workspace/list"),
            ("GET", "/user/team/list"),
            ("POST", "/user/team/list"),
            ("GET", "/api/workspace/list"),
            ("POST", "/api/workspace/list"),
            ("GET", "/api/team/list"),
            ("POST", "/api/team/list"),
            ("GET", "/browser/workspace/list"),
            ("POST", "/browser/workspace/list"),
            ("GET", "/browser/team/list"),
            ("POST", "/browser/team/list"),
        ])

        errors = []
        seen = set()
        for m, path in candidates:
            key = (m, path)
            if key in seen:
                continue
            seen.add(key)
            ok, payload = self.try_request(m, path)
            if not ok:
                errors.append({"method": m, "path": path, "error": payload})
                continue
            items = self._extract_workspace_items(payload if isinstance(payload, dict) else {})
            if items:
                return {"ok": True, "path": path, "method": m, "items": items, "raw": payload}
            errors.append({"method": m, "path": path, "error": "响应中未解析到团队/工作区列表", "payload": payload})

        return {"ok": False, "items": [], "errors": errors}

    def create_profile(self, payload: dict | None = None) -> str:
        payload = dict(payload or {})
        skip_proxy_pool = bool(payload.pop("__skip_proxy_pool", False))
        body = dict(getattr(_cfg, "ROXY_PROFILE_CREATE_PAYLOAD", {}) or {})
        random_name_enabled = bool(getattr(_cfg, "ROXY_RANDOM_PROFILE_NAME_ON_CREATE", True))
        if random_name_enabled:
            # 覆盖 ROXY_PROFILE_CREATE_PAYLOAD 里的固定 name，避免所有 Roxy 窗口同名。
            generated_name = _random_roxy_profile_name()
            body["name"] = generated_name  # 兼容旧版字段。
            body["windowName"] = generated_name  # 当前 Roxy API 字段，亦用于超时后幂等查找。
        random_os_enabled = bool(getattr(_cfg, "ROXY_RANDOM_OS_ON_CREATE", True))
        if random_os_enabled:
            # 每次创建环境随机 Windows / macOS；覆盖 ROXY_PROFILE_CREATE_PAYLOAD 里的固定 os。
            body["os"] = _random_roxy_os()
            # osVersion 跟 os 强绑定，随机 OS 时不沿用固定版本，避免 macOS 版本传给 Windows。
            body.pop("osVersion", None)
        else:
            default_os = str(getattr(_cfg, "ROXY_DEFAULT_OS", "macOS") or "macOS").strip()
            if default_os:
                # Roxy 官方枚举大小写敏感：Windows / macOS / Linux / IOS / Android。
                body.setdefault("os", default_os)
            default_os_version = str(getattr(_cfg, "ROXY_DEFAULT_OS_VERSION", "") or "").strip()
            if default_os_version:
                body.setdefault("osVersion", default_os_version)
        workspace_id = _workspace_id_value()
        if workspace_id:
            # Roxy 官方 /browser/create 要求 workspaceId。
            body.setdefault("workspaceId", workspace_id)
        project_id = _project_id_value()
        if project_id:
            body.setdefault("projectId", project_id)
        if bool(getattr(_cfg, "ROXY_CREATE_USE_PROXY_POOL", False)) and not body.get("proxyInfo") and not skip_proxy_pool:
            from config import proxy as _proxy_cfg

            candidates = [str(item).strip() for item in (getattr(_proxy_cfg, "PROXY_POOL", []) or []) if str(item).strip()]
            random.shuffle(candidates)
            candidates = _reserve_proxy_candidates(candidates)
            max_attempts = int(getattr(_cfg, "ROXY_PROXY_POOL_CREATE_MAX_ATTEMPTS", 0) or 0)
            if max_attempts > 0:
                candidates = candidates[:max_attempts]
            chain_handle = None
            if candidates:
                last_exc: Exception | None = None
                for attempt, proxy_url in enumerate(candidates, 1):
                    try:
                        source_proxy_url = _normalize_proxy_url(proxy_url, default_scheme=_roxy_pool_default_scheme())
                        roxynet = _register_official_roxynet_proxy(source_proxy_url)
                        if roxynet is not None:
                            proxy_for_roxy, chain_handle = roxynet
                        else:
                            proxy_for_roxy, chain_handle = _maybe_start_proxy_chain(source_proxy_url)
                        normalized_proxy_url = _normalize_proxy_url(proxy_for_roxy, default_scheme=_roxy_pool_default_scheme())
                        proxy_info = _proxy_url_to_roxy_info(normalized_proxy_url)
                        body["proxyInfo"] = proxy_info
                        # roxy-unlimited-windows accepts a simple `proxy` URL while
                        # official RoxyBrowser accepts/ignores the richer `proxyInfo`.
                        # Send both so this client works with either local API.
                        body.setdefault("proxy", normalized_proxy_url)
                        if chain_handle is not None:
                            body.setdefault("__chain_handle", chain_handle)
                        body.setdefault("__proxy_used", normalized_proxy_url)
                        _mark_proxy_reserved(source_proxy_url)
                        logger.info(
                            "[Roxy] 创建环境启用代理池：attempt=%s/%s source=%s roxy_proxy=%s type=%s host=%s port=%s",
                            attempt,
                            len(candidates),
                            _mask_proxy(proxy_url),
                            _mask_proxy(normalized_proxy_url),
                            proxy_info.get("protocol") or proxy_info.get("proxyCategory"),
                            proxy_info.get("host"),
                            proxy_info.get("port"),
                        )
                        break
                    except Exception as exc:
                        last_exc = exc
                        logger.warning(
                            "[Roxy] 代理池候选不可用，跳过：attempt=%s/%s source=%s error=%s",
                            attempt,
                            len(candidates),
                            _mask_proxy(proxy_url),
                            str(exc)[:240],
                        )
                if not body.get("proxyInfo"):
                    raise RuntimeError(f"Roxy 代理池没有可用代理，已尝试 {len(candidates)} 个；最后错误：{last_exc}")
            else:
                logger.warning("[Roxy] 已启用 ROXY_CREATE_USE_PROXY_POOL，但 PROXY_POOL 为空，本次创建环境不设置代理")
        if payload:
            body.update(payload)
        # roxy-unlimited-windows warns that omitting `proxy` may inherit an old
        # template proxy. Default to direct when no proxy pool/payload provided.
        body.setdefault("proxy", "direct")
        if not body.get("workspaceId"):
            raise RuntimeError(
                "Roxy 创建环境需要 workspaceId。请在 config/roxybrowser.py 或 WebUI 的 RoxyBrowser 配置中填写 ROXY_WORKSPACE_ID，"
                "或直接在 ROXY_PROFILE_CREATE_PAYLOAD 里加入 {'workspaceId': '你的工作区ID'}。"
            )
        chain_handle = body.pop("__chain_handle", None)
        proxy_used = body.pop("__proxy_used", None) or (
            str(body.get("proxy") or "").strip()
            if str(body.get("proxy") or "").strip().lower() not in ("", "direct")
            else None
        )
        logger.info(
            "[Roxy] 创建环境参数：workspaceId=%s projectId=%s name=%s random_name=%s os=%s osVersion=%s random_os=%s",
            body.get("workspaceId"),
            body.get("projectId") or "-",
            body.get("name") or "-",
            random_name_enabled,
            body.get("os") or "-",
            body.get("osVersion") or "-",
            random_os_enabled,
        )
        try:
            result = self.request(_cfg.ROXY_CREATE_METHOD, _cfg.ROXY_CREATE_PATH, json_body=body)
        except RuntimeError as exc:
            # Roxy 会把自身创建链路的 15 秒 axios 超时作为 code/msg 正常回包。
            # 该情况不能直接多次 create：首次请求可能已在服务端完成。先等待并按唯一
            # windowName 查找；确认未创建时才额外重试一次。
            text = str(exc).lower()
            name = str(body.get("windowName") or body.get("name") or "").strip()
            if "timeout" not in text or not name:
                raise
            delay = max(1.0, float(getattr(_cfg, "ROXY_API_RETRY_DELAY", 2) or 2))
            logger.warning("[Roxy] 创建环境返回超时，%.1fs 后核对同名 Profile：name=%s", delay, name)
            time.sleep(delay)
            existing_id = self._find_profile_by_window_name(body.get("workspaceId"), name)
            if existing_id:
                logger.warning("[Roxy] 创建请求超时但同名 Profile 已存在，复用 dirId=%s", existing_id)
                return existing_id
            logger.warning("[Roxy] 创建超时后未发现同名 Profile，安全重试一次：name=%s", name)
            result = self.request(_cfg.ROXY_CREATE_METHOD, _cfg.ROXY_CREATE_PATH, json_body=body)
        profile_id = _first(result, [
            ("id",), ("dirId",), ("dir_id",), ("profile_id",), ("profileId",), ("browser_id",),
            ("data", "id"), ("data", "dirId"), ("data", "dir_id"),
            ("data", "profile_id"), ("data", "profileId"), ("data", "browser_id"),
        ])
        if not profile_id:
            if chain_handle is not None:
                try:
                    chain_handle.stop()
                except Exception:
                    pass
            raise RuntimeError(f"Roxy 创建环境成功但未返回 dirId/profile_id: {result}")
        if chain_handle is not None:
            self._proxy_chain_by_profile[str(profile_id)] = chain_handle
            logger.info("[Roxy] Profile 绑定本地链式代理：profile=%s local=%s", profile_id, getattr(chain_handle, "local_proxy", "-"))
        if proxy_used:
            self._proxy_used_by_profile[str(profile_id)] = str(proxy_used)
        return profile_id

    @staticmethod
    def _normalize_profile_id(value: str | None) -> str:
        text = str(value or "").strip()
        # WebUI/人工配置里常用 - 表示“未配置”，这里统一按空处理。
        if text in ("-", "—", "无", "空", "none", "None", "null", "NULL"):
            return ""
        return text

    def open_profile(self, profile_id: str | None = None, *, payload: dict | None = None) -> RoxyOpenResult:
        one_profile = bool(getattr(_cfg, "ROXY_ONE_PROFILE_PER_ACCOUNT", True))
        explicit_profile_id = profile_id is not None
        configured_pid = self._normalize_profile_id(profile_id if explicit_profile_id else getattr(_cfg, "ROXY_PROFILE_ID", ""))
        if one_profile and configured_pid and not explicit_profile_id:
            raise RuntimeError(
                "已启用 ROXY_ONE_PROFILE_PER_ACCOUNT=True（一号一环境），"
                "不能配置固定 ROXY_PROFILE_ID；请留空以便每个账号创建新环境。"
            )

        pid = configured_pid
        created_by_run = False
        if not pid:
            pid = self.create_profile(payload=payload)
            created_by_run = True
            logger.info("[Roxy] 已创建临时环境：%s", pid)

        path = str(_cfg.ROXY_OPEN_PATH).format(profile_id=pid)
        params = dict(getattr(_cfg, "ROXY_OPEN_EXTRA_PARAMS", {}) or {})
        # Roxy 官方 /browser/open body: {workspaceId, dirId, args, forceOpen, headless}
        params.setdefault("workspaceId", _workspace_id_value())
        params.setdefault("dirId", int(pid) if str(pid).isdigit() else pid)
        params.setdefault("args", [])
        params.setdefault("forceOpen", True)
        _apply_data_saver_open_args(params)
        # ROXY_OPEN_HEADLESS 是显式开关，优先级应高于 ROXY_OPEN_EXTRA_PARAMS，
        # 否则 extra 里残留 headless=False 会导致 WebUI 保存无头后仍弹窗口。
        params["headless"] = bool(getattr(_cfg, "ROXY_OPEN_HEADLESS", False))
        logger.info("[Roxy] open 参数：profile=%s headless=%s keep_open=%s", pid, params.get("headless"), getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False))
        result = self.request(
            _cfg.ROXY_OPEN_METHOD,
            path,
            params=params if _cfg.ROXY_OPEN_METHOD.upper() == "GET" else None,
            json_body=params if _cfg.ROXY_OPEN_METHOD.upper() != "GET" else None,
        )
        debugger_address = self._extract_debugger_address(result)
        logger.info("[Roxy] open 返回摘要: debugger=%s raw=%s", debugger_address, json.dumps(result, ensure_ascii=False)[:800])
        webdriver_url = _first(result, [
            ("webdriver",), ("webDriver",), ("webdriver_url",), ("webdriverUrl",),
            ("selenium",), ("selenium_url",), ("seleniumUrl",),
            ("data", "webdriver"), ("data", "webDriver"), ("data", "webdriver_url"), ("data", "webdriverUrl"),
            ("data", "selenium"), ("data", "selenium_url"), ("data", "seleniumUrl"),
        ]) or None
        ws_endpoint = _first(result, [
            ("ws",), ("wsEndpoint",), ("ws_endpoint",), ("debuggerWsUrl",),
            ("data", "ws"), ("data", "wsEndpoint"), ("data", "ws_endpoint"), ("data", "debuggerWsUrl"),
        ]) or None
        if not debugger_address and not webdriver_url:
            raise RuntimeError(f"Roxy 已打开环境但未返回 Selenium/调试地址，请检查 ROXY_OPEN_PATH 或接口响应: {result}")
        return RoxyOpenResult(
            pid,
            result,
            debugger_address=debugger_address,
            webdriver_url=webdriver_url,
            ws_endpoint=ws_endpoint,
            created_by_run=created_by_run,
            proxy_chain_handle=self._proxy_chain_by_profile.get(str(pid)),
            proxy_used=self._proxy_used_by_profile.get(str(pid)),
        )

    def close_profile(self, profile_id: str, *, timeout: float | int | None = None) -> None:
        if not profile_id:
            return
        path = str(_cfg.ROXY_CLOSE_PATH).format(profile_id=profile_id)
        try:
            body = {
                "workspaceId": _workspace_id_value(),
                "dirId": int(profile_id) if str(profile_id).isdigit() else profile_id,
            }
            self.request(
                _cfg.ROXY_CLOSE_METHOD,
                path,
                params=body if str(_cfg.ROXY_CLOSE_METHOD).upper() == "GET" else None,
                json_body=body if str(_cfg.ROXY_CLOSE_METHOD).upper() != "GET" else None,
                timeout=timeout,
            )
            logger.info("[Roxy] 已关闭环境：%s", profile_id)
        except Exception as exc:
            logger.warning("[Roxy] 关闭环境失败：%s", exc)

    def delete_profile(self, profile_id: str, *, timeout: float | int | None = None) -> None:
        if not profile_id:
            return
        path = str(getattr(_cfg, "ROXY_DELETE_PATH", "/browser/delete")).format(profile_id=profile_id)
        method = str(getattr(_cfg, "ROXY_DELETE_METHOD", "POST") or "POST")
        try:
            profile_value = int(profile_id) if str(profile_id).isdigit() else profile_id
            body = {
                "workspaceId": _workspace_id_value(),
                # official RoxyBrowser commonly uses dirIds; roxy-unlimited-windows
                # expects a single dirId. Include both for compatibility.
                "dirId": profile_value,
                "dirIds": [profile_value],
            }
            self.request(
                method,
                path,
                params=body if method.upper() == "GET" else None,
                json_body=body if method.upper() != "GET" else None,
                timeout=timeout,
            )
            logger.info("[Roxy] 已删除环境：%s", profile_id)
        except Exception as exc:
            logger.warning("[Roxy] 删除环境失败：%s", exc)

    def cleanup_profile(self, opened: RoxyOpenResult | None) -> None:
        """任务结束清理：关闭窗口；一号一环境时删除本轮创建的 Profile。"""
        if not opened or not opened.profile_id:
            return
        keep_open = bool(getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False))
        if not keep_open:
            self.close_profile(opened.profile_id, timeout=8)

        should_delete = (
            bool(getattr(_cfg, "ROXY_ONE_PROFILE_PER_ACCOUNT", True))
            and bool(getattr(_cfg, "ROXY_DELETE_PROFILE_AFTER_RUN", True))
            and bool(opened.created_by_run)
        )
        if should_delete:
            # 删除前尽量确保已关闭；若 keep_open=True 则不删除，便于调试保留现场。
            if keep_open:
                logger.info("[Roxy] ROXY_KEEP_BROWSER_OPEN=True，跳过删除环境：%s", opened.profile_id)
                return
            self.delete_profile(opened.profile_id, timeout=8)

        chain_handle = self._proxy_chain_by_profile.pop(str(opened.profile_id), None) or getattr(opened, "proxy_chain_handle", None)
        self._proxy_used_by_profile.pop(str(opened.profile_id), None)
        if chain_handle is not None:
            try:
                chain_handle.stop()
                logger.info("[Roxy] 已停止本地链式代理：profile=%s local=%s", opened.profile_id, getattr(chain_handle, "local_proxy", "-"))
            except Exception as exc:
                logger.warning("[Roxy] 停止本地链式代理失败：profile=%s error=%s", opened.profile_id, exc)

    @staticmethod
    def _extract_debugger_address(payload: dict) -> str | None:
        value = _first(payload, [
            ("debuggerAddress",), ("debugger_address",), ("debugAddress",),
            ("debuggingPortUrl",), ("debugging_port_url",),
            ("remoteDebuggingAddress",), ("remote_debugging_address",),
            ("http",), ("debugHttp",), ("debug_http",),
            ("data", "debuggerAddress"), ("data", "debugger_address"), ("data", "debugAddress"),
            ("data", "debuggingPortUrl"), ("data", "debugging_port_url"),
            ("data", "remoteDebuggingAddress"), ("data", "remote_debugging_address"),
            ("data", "http"), ("data", "debugHttp"), ("data", "debug_http"),
        ])
        if value:
            value = value.strip()
            # 兼容 http://127.0.0.1:xxxx / 127.0.0.1:xxxx / :xxxx / 9222
            value = value.replace("http://", "").replace("https://", "").strip("/")
            if value.startswith(":") and value[1:].isdigit():
                return f"127.0.0.1{value}"
            if value.isdigit():
                return f"127.0.0.1:{value}"
            if ":" in value and not value.startswith(":"):
                return value
        port = _first(payload, [
            ("debuggingPort",), ("debugging_port",), ("debug_port",), ("port",),
            ("data", "debuggingPort"), ("data", "debugging_port"), ("data", "debug_port"), ("data", "port"),
        ])
        if port:
            port = str(port).strip()
            if port.startswith(":"):
                port = port[1:]
            if port.isdigit():
                return f"127.0.0.1:{port}"
        return None
