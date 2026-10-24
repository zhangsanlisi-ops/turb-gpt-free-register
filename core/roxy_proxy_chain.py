# -*- coding: utf-8 -*-
"""Local proxy-chain helper for RoxyBrowser.

Roxy official launcher can route target proxies through a local/system proxy
(e.g. 1024proxy -> http://127.0.0.1:7897). roxy-unlimited launches the browser
kernel directly, so this module provides the missing local HTTP entrypoint:

    RoxyChrome -> http://127.0.0.1:<local_port>
      -> SOCKS5 target proxy (host:port:user:pass)
      -> upstream HTTP proxy (127.0.0.1:7897)

It is intentionally stdlib-only and process-local. Handles are stopped by
RoxyBrowserClient.cleanup_profile().
"""
from __future__ import annotations

import base64
import logging
import select
import socket
import socketserver
import struct
import threading
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlparse

logger = logging.getLogger(__name__)


@dataclass
class ProxyChainHandle:
    original_proxy: str
    local_proxy: str
    listen_host: str
    listen_port: int
    target_host: str
    target_port: int
    target_scheme: str
    target_user: str
    upstream_proxy: str
    server: socketserver.ThreadingTCPServer
    thread: threading.Thread

    def stop(self) -> None:
        try:
            self.server.shutdown()
        except Exception:
            pass
        try:
            self.server.server_close()
        except Exception:
            pass
        try:
            self.thread.join(timeout=2)
        except Exception:
            pass


_LOCK = threading.RLock()
_NEXT_OFFSET = 0


def _recv_until(sock: socket.socket, marker: bytes = b"\r\n\r\n", limit: int = 65536) -> bytes:
    data = b""
    while marker not in data and len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _split_host_port(value: str) -> tuple[str, int]:
    parsed = urlparse(value if "://" in value else f"http://{value}")
    if not parsed.hostname or not parsed.port:
        raise ValueError(f"upstream proxy must include host/port: {value}")
    return parsed.hostname, int(parsed.port)


def _parse_target_proxy(proxy: str) -> tuple[str, int, str, str, str]:
    text = str(proxy or "").strip()
    if not text:
        raise ValueError("proxy is empty")
    scheme = "http"
    if "://" in text:
        parsed = urlparse(text)
        if not parsed.hostname or not parsed.port:
            raise ValueError(f"proxy missing host/port: {text}")
        scheme = (parsed.scheme or "http").lower()
        if scheme == "socks5h":
            scheme = "socks5"
        return parsed.hostname, int(parsed.port), scheme, unquote(parsed.username or ""), unquote(parsed.password or "")
    parts = text.split(":")
    if len(parts) >= 4 and parts[1].isdigit():
        return parts[0], int(parts[1]), scheme, parts[2], ":".join(parts[3:])
    raise ValueError(f"unsupported target proxy format for local chain: {text}")


def looks_like_1024_proxy(proxy: str) -> bool:
    text = str(proxy or "").strip().lower()
    return "1024proxy.io" in text


class _ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _make_handler(target_host: str, target_port: int, target_scheme: str, username: str, password: str, upstream_proxy: str):
    upstream_host, upstream_port = _split_host_port(upstream_proxy)
    user_b = username.encode("utf-8")
    pass_b = password.encode("utf-8")
    auth_header = ""
    if username or password:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        auth_header = f"Proxy-Authorization: Basic {token}\r\n"

    def connect_target_via_upstream() -> socket.socket:
        s = socket.create_connection((upstream_host, upstream_port), timeout=20)
        req = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            "Proxy-Connection: Keep-Alive\r\n"
            "\r\n"
        ).encode("latin1")
        s.sendall(req)
        resp = _recv_until(s)
        first = resp.split(b"\r\n", 1)[0]
        if b" 200 " not in first and not first.endswith(b" 200"):
            raise OSError(f"upstream CONNECT target failed: {first!r}")
        return s

    def socks5_connect(s: socket.socket, host: str, port: int) -> None:
        # username/password auth
        s.sendall(b"\x05\x01\x02")
        method = s.recv(2)
        if method != b"\x05\x02":
            raise OSError(f"SOCKS5 auth method failed: {method!r}")
        if len(user_b) > 255 or len(pass_b) > 255:
            raise OSError("SOCKS5 username/password too long")
        s.sendall(b"\x01" + bytes([len(user_b)]) + user_b + bytes([len(pass_b)]) + pass_b)
        auth_resp = s.recv(2)
        if auth_resp != b"\x01\x00":
            raise OSError(f"SOCKS5 auth failed: {auth_resp!r}")
        host_b = host.encode("idna")
        if len(host_b) > 255:
            raise OSError(f"SOCKS5 destination host too long: {host}")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", int(port)))
        head = s.recv(4)
        if len(head) < 4:
            raise OSError(f"SOCKS5 connect short response: {head!r}")
        atyp = head[3]
        if atyp == 1:
            rest = s.recv(6)
        elif atyp == 3:
            ln_b = s.recv(1)
            ln = ln_b[0] if ln_b else 0
            rest = s.recv(ln + 2)
        elif atyp == 4:
            rest = s.recv(18)
        else:
            rest = b""
        if head[1] != 0:
            raise OSError(f"SOCKS5 connect failed rep={head[1]} rest={rest!r}")

    def http_proxy_connect(s: socket.socket, host: str, port: int) -> None:
        req = (
            f"CONNECT {host}:{int(port)} HTTP/1.1\r\n"
            f"Host: {host}:{int(port)}\r\n"
            f"{auth_header}"
            "Proxy-Connection: Keep-Alive\r\n"
            "\r\n"
        ).encode("latin1")
        s.sendall(req)
        resp = _recv_until(s)
        first = resp.split(b"\r\n", 1)[0]
        if b" 200 " not in first and not first.endswith(b" 200"):
            raise OSError(f"HTTP target proxy CONNECT failed: {first!r}")

    def inject_http_proxy_auth(req: bytes) -> bytes:
        if not auth_header:
            return req
        if b"\r\nProxy-Authorization:" in req or req.startswith(b"Proxy-Authorization:"):
            return req
        marker = b"\r\n"
        pos = req.find(marker)
        if pos < 0:
            return req
        return req[: pos + 2] + auth_header.encode("latin1") + req[pos + 2 :]

    def pipe(a: socket.socket, b: socket.socket) -> None:
        sockets = [a, b]
        try:
            while True:
                ready, _, _ = select.select(sockets, [], [], 120)
                if not ready:
                    break
                for s in ready:
                    data = s.recv(65536)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        finally:
            for s in sockets:
                try:
                    s.close()
                except Exception:
                    pass

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            upstream_sock: socket.socket | None = None
            try:
                req = _recv_until(self.request)
                if not req:
                    return
                first_line = req.split(b"\r\n", 1)[0].decode("latin1", "ignore")
                parts = first_line.split(" ", 2)
                if len(parts) < 3:
                    raise OSError(f"bad HTTP proxy request line: {first_line!r}")
                method, target, _version = parts
                if method.upper() != "CONNECT":
                    # Plain HTTP proxy requests can be forwarded to the target HTTP proxy.
                    if target_scheme not in ("http", "https"):
                        body = b"Only CONNECT is supported for SOCKS5 target proxy chain"
                        self.request.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
                        return
                    upstream_sock = connect_target_via_upstream()
                    upstream_sock.sendall(inject_http_proxy_auth(req))
                    pipe(self.request, upstream_sock)
                    upstream_sock = None
                    return
                dst_host, dst_port_s = target.rsplit(":", 1)
                upstream_sock = connect_target_via_upstream()
                if target_scheme in ("socks5", "socks"):
                    socks5_connect(upstream_sock, dst_host.strip("[]"), int(dst_port_s))
                elif target_scheme in ("http", "https"):
                    http_proxy_connect(upstream_sock, dst_host.strip("[]"), int(dst_port_s))
                else:
                    raise OSError(f"unsupported target proxy scheme for local chain: {target_scheme}")
                self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                pipe(self.request, upstream_sock)
                upstream_sock = None
            except Exception as exc:
                logger.debug("[RoxyChain] request failed: %s", exc)
                body = str(exc).encode("utf-8", "replace")
                try:
                    self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
                except Exception:
                    pass
            finally:
                if upstream_sock is not None:
                    try:
                        upstream_sock.close()
                    except Exception:
                        pass

    return Handler


def start_proxy_chain(
    proxy: str,
    *,
    upstream_proxy: str = "http://127.0.0.1:7897",
    listen_host: str = "127.0.0.1",
    base_port: int = 18100,
    max_ports: int = 200,
) -> ProxyChainHandle:
    """Start a local HTTP CONNECT proxy for one authenticated target proxy.

    This is used when the Roxy profile must use a provider proxy through a
    local upstream proxy.  The target proxy may be HTTP(S) or SOCKS5.
    """
    global _NEXT_OFFSET
    target_host, target_port, target_scheme, username, password = _parse_target_proxy(proxy)
    if not username or not password:
        raise ValueError("target proxy chain requires username/password")
    handler_cls = _make_handler(target_host, target_port, target_scheme, username, password, upstream_proxy)
    last_exc: Exception | None = None
    with _LOCK:
        for i in range(max_ports):
            port = int(base_port) + ((_NEXT_OFFSET + i) % int(max_ports))
            try:
                server = _ReusableThreadingTCPServer((listen_host, port), handler_cls)
                _NEXT_OFFSET = ((_NEXT_OFFSET + i + 1) % int(max_ports))
                break
            except OSError as exc:
                last_exc = exc
        else:
            raise RuntimeError(f"no free local proxy-chain port in {base_port}-{base_port + max_ports - 1}: {last_exc}")
    thread = threading.Thread(target=server.serve_forever, name=f"roxy-proxy-chain-{port}", daemon=True)
    thread.start()
    local_proxy = f"http://{listen_host}:{port}"
    logger.info(
        "[RoxyChain] started local proxy chain %s -> %s://%s:***@%s:%s -> %s",
        local_proxy,
        target_scheme,
        username,
        target_host,
        target_port,
        upstream_proxy,
    )
    return ProxyChainHandle(
        original_proxy=str(proxy),
        local_proxy=local_proxy,
        listen_host=listen_host,
        listen_port=port,
        target_host=target_host,
        target_port=target_port,
        target_scheme=target_scheme,
        target_user=username,
        upstream_proxy=upstream_proxy,
        server=server,
        thread=thread,
    )
