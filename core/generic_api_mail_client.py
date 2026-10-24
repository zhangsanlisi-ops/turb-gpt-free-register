# -*- coding: utf-8 -*-
"""
通用 API 取码邮箱客户端。

邮箱池导入格式：
    email----code_url

注册时领取 email；取码时直接 GET code_url，并从响应中提取 6 位验证码。
响应可以是纯文本、HTML 或 JSON，只要其中包含 6 位验证码即可。
"""
import json
import logging
import re
import time
import base64
import html as html_lib
import shutil
import subprocess
from datetime import datetime
from dataclasses import dataclass
from types import SimpleNamespace
from pathlib import Path
from urllib.parse import quote, unquote, urlparse, urlunparse, parse_qsl, urlencode

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp

logger = logging.getLogger(__name__)

_CODE_REGEX = re.compile(r"\b(\d{6})\b")
_CONTEXT_WORDS = ("code", "verify", "verification", "验证码", "代码", "确认码", "認証", "コード", "mã xác minh", "ma xac minh")
_CONTEXT_CACHE: dict[str, "GenericApiEmailAccount"] = {}
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ACCOUNTS_FILE = _PROJECT_ROOT / "用于注册的API邮箱.txt"
_YANGYANG_MESSAGES_RE = re.compile(r"/messages/([^/]+)/([^/?#]+)", re.IGNORECASE)
_ZHANGBINBIN_MAIL_RE = re.compile(r"/mail/([^/]+)/([^/?#]+)", re.IGNORECASE)
_ZHANGBINBIN_OPENAPI_RE = re.compile(r"/openapi/mail/([^/]+)/([^/?#]+)(?:/latest)?", re.IGNORECASE)
_ZHANGBINBIN_HOST = "mail.zhangbinbin.edu.kg"
_ZHANGBINBIN_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
_YANGYANG_OPENAI_SUBJECT_HINTS = (
    "temporary chatgpt",
    "chatgpt verification code",
    "chatgpt login code",
    "临时 chatgpt",
    "chatgpt 登录代码",
    "chatgpt 验证码",
    "一時的な認証コード",
    "一時ログインコード",
)


class GenericApiMailError(RuntimeError):
    """通用 API 取码邮箱错误。"""


class GenericApiPickupInvalidError(GenericApiMailError):
    """取件地址本身无效，继续轮询或重发 OTP 都没意义。"""


def _mask_sensitive_url(url: str) -> str:
    """日志/错误里隐藏取码 URL 的 token，避免把邮箱 API 凭证打出去。"""
    try:
        parsed = urlparse(str(url))
        parts = [p for p in (parsed.path or "").split("/") if p]
        masked: list[str] = []
        for part in parts:
            decoded = unquote(part)
            if "@" in decoded:
                masked.append(quote(decoded, safe="@")[:32] + ("..." if len(decoded) > 32 else ""))
            elif len(part) >= 20:
                masked.append(part[:4] + "..." + part[-4:])
            else:
                masked.append(part)
        path = "/" + "/".join(masked) if masked else parsed.path
        return urlunparse(parsed._replace(path=path, query="" if parsed.query else parsed.query))
    except Exception:
        return "<masked-url>"


def _configured_proxy_candidates() -> list[str]:
    """返回 Generic API 可用的代理兜底列表，去重且保留顺序。"""
    out: list[str] = []

    def add(value) -> None:
        if isinstance(value, (list, tuple)):
            for item in value:
                add(item)
            return
        raw = str(value or "").strip().strip('"\'')
        if raw and raw not in out:
            out.append(raw)

    add(getattr(_email_cfg, "GENERIC_API_MAIL_PROXY", ""))
    add(getattr(_email_cfg, "GENERIC_API_MAIL_PROXY_POOL", []) or [])
    # 复用当前项目里已经配置好的本地代理兜底，但只在用户确实配置时使用。
    try:
        from config import roxybrowser as _roxy_cfg
        add(getattr(_roxy_cfg, "ROXY_PROXY_CHAIN_UPSTREAM", ""))
    except Exception:
        pass
    return out


def _curl_get(
    url: str,
    *,
    headers: dict,
    timeout: int,
    proxy: str | None = None,
):
    curl = shutil.which("curl.exe") or shutil.which("curl")
    if not curl:
        return None, "curl not found"
    command = [
        curl,
        "-sS",
        "--connect-timeout",
        "8",
        "--max-time",
        str(timeout),
        "--retry",
        "1",
        "--retry-delay",
        "1",
    ]
    if proxy:
        command.extend(["--proxy", proxy])
    for key, value in headers.items():
        command.extend(["-H", f"{key}: {value}"])
    command.extend(["-w", "\n__HTTP_STATUS__:%{http_code}", url])
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 6, check=False)
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"

    body, separator, raw_status = completed.stdout.rpartition("\n__HTTP_STATUS__:")
    status = int(raw_status.strip()) if separator and raw_status.strip().isdigit() else 0
    if completed.returncode == 0 and status:
        return SimpleNamespace(status_code=status, text=body), None
    err = (completed.stderr or completed.stdout or "").strip().replace("\r", " ").replace("\n", " ")
    return None, f"curl exit={completed.returncode} status={status or '-'} {err[:220]}"


def _get_with_connection_fallback(
    session: requests.Session,
    url: str,
    *,
    headers: dict,
    timeout: int = 20,
):
    """Fetch Generic API; prefer configured proxy, then direct/curl fallback."""
    attempts: list[str] = []
    proxy_candidates = _configured_proxy_candidates()

    # The local host often cannot connect to the public pickup domain directly,
    # while the configured local proxy can. Prefer proxy to avoid one failed
    # direct connection on every OTP polling round.
    for proxy in proxy_candidates:
        try:
            proxied = requests.Session()
            proxied.proxies.update({"http": proxy, "https": proxy})
            resp = proxied.get(url, headers=headers, timeout=timeout, verify=False)
            logger.info("[GenericAPI] proxy fetch ok: proxy=%s HTTP %s", proxy, resp.status_code)
            return resp
        except Exception as exc:
            attempts.append(f"requests proxy {proxy}: {type(exc).__name__}")

    try:
        return session.get(url, headers=headers, timeout=timeout, verify=False)
    except requests.exceptions.ConnectionError as original_error:
        attempts.append(f"requests direct: {type(original_error).__name__}")
    except requests.exceptions.SSLError as ssl_error:
        attempts.append(f"requests direct ssl: {type(ssl_error).__name__}")
    except requests.exceptions.ProxyError as proxy_error:
        attempts.append(f"requests direct proxy: {type(proxy_error).__name__}")
    except requests.exceptions.Timeout as timeout_error:
        attempts.append(f"requests direct timeout: {type(timeout_error).__name__}")
    else:  # pragma: no cover
        return None

    for proxy in [None] + proxy_candidates:
        resp, err = _curl_get(url, headers=headers, timeout=timeout, proxy=proxy)
        if resp is not None:
            logger.info(
                "[GenericAPI] curl fallback ok: proxy=%s HTTP %s",
                proxy or "direct",
                resp.status_code,
            )
            return resp
        attempts.append(f"curl {proxy or 'direct'}: {err}")

    logger.warning(
        "[GenericAPI] all connection fallbacks failed url=%s attempts=%s",
        _mask_sensitive_url(url),
        " | ".join(attempts[-6:]),
    )
    raise GenericApiMailError(
        "pickup API connection failed: direct/proxy/curl unavailable; "
        f"url={_mask_sensitive_url(url)}; last={attempts[-1] if attempts else 'unknown'}"
    )

def _cache_busted_url(url: str, attempt: int) -> str:
    """给取码接口加缓存破坏参数，避免 CDN/反向代理一直返回上一封验证码。"""
    try:
        parsed = urlparse(str(url))
        query = parse_qsl(parsed.query, keep_blank_values=True)
        query.append(("_otp_poll", f"{int(time.time() * 1000)}-{attempt}"))
        return urlunparse(parsed._replace(query=urlencode(query)))
    except Exception:
        return url

def _append_query_params(url: str, params: dict[str, str | int]) -> str:
    try:
        parsed = urlparse(str(url))
        query = parse_qsl(parsed.query, keep_blank_values=True)
        query.extend((str(k), str(v)) for k, v in params.items())
        return urlunparse(parsed._replace(query=urlencode(query)))
    except Exception:
        return url


@dataclass
class GenericApiEmailAccount:
    email: str
    code_url: str


def _flatten_json(obj) -> str:
    parts: list[str] = []
    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif x is not None:
            parts.append(str(x))
    walk(obj)
    return "\n".join(parts)


def _decode_data_uri(text: str) -> str:
    """把 data:text/html;base64,... 正文解码成可抽取 OTP 的 HTML/文本。"""
    if not isinstance(text, str):
        return ""
    if not text.startswith("data:"):
        return text
    try:
        _meta, payload = text.split(",", 1)
    except ValueError:
        return text
    if ";base64" in _meta.lower():
        try:
            return base64.b64decode(payload).decode("utf-8", errors="replace")
        except Exception:
            return text
    try:
        from urllib.parse import unquote_to_bytes
        return unquote_to_bytes(payload).decode("utf-8", errors="replace")
    except Exception:
        return text


def _extract_code(text: str) -> str | None:
    """从纯文本/HTML/JSON 文本中提取 6 位 OTP。"""
    if not text:
        return None

    # 兼容 JSON：优先把所有 value 拉平再抽取。
    candidates_text = [_decode_data_uri(text), text]
    try:
        parsed = json.loads(text)
        candidates_text.insert(0, _decode_data_uri(_flatten_json(parsed)))
    except Exception:
        pass

    for body in candidates_text:
        # 复用邮件 OTP 抽取逻辑。
        code = extract_otp({"text": body, "content": body, "subject": body[:200]})
        if code:
            return code

        codes = _CODE_REGEX.findall(body)
        if not codes:
            continue
        lower = body.lower()
        for code in codes:
            idx = lower.find(code)
            window = lower[max(0, idx - 80): idx + 86]
            if any(w.lower() in window for w in _CONTEXT_WORDS):
                return code
        return codes[-1]
    return None


def _extract_yangyang_openai_code(subject: str, body: str) -> str | None:
    """
    yangyang 邮件详情里 OpenAI 模板常混入多个 6 位数字：
    - 202123 / 353740 这类 CSS/模板数字
    - 真正 OTP 在 “Your code is / code:” 附近，通常是正文最后一个业务 6 位数
    所以不能直接复用通用 _extract_code 的“第一个上下文命中”。
    """
    body = _decode_data_uri(body or "")
    subject_l = (subject or "").lower()
    text = "\n".join([subject or "", body])

    # 去掉 style/script，减少 CSS 颜色、宽高等 6 位数字干扰。
    clean = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"<script[^>]*>.*?</script>", " ", clean, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"#[0-9a-fA-F]{6}\b", " ", clean)
    clean = re.sub(r"(?:color|background|border|width|height|font-size|line-height)\s*:\s*[^;\"']+", " ", clean, flags=re.IGNORECASE)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = re.sub(r"\s+", " ", clean).strip()

    codes = _CODE_REGEX.findall(clean)
    if not codes:
        return None

    # 过滤已知模板噪声；保留其它 6 位候选。
    noise = {"000000", "202123", "353740"}
    candidates = [c for c in codes if c not in noise]
    if not candidates:
        candidates = codes

    lower = clean.lower()
    patterns = (
        r"(?:code is|code:|verification code is|login code is|your code is)\D{0,80}(\d{6})",
        r"(?:验证码|驗證碼|登录代码|登入代碼|確認コード|認証コード|ログインコード)\D{0,80}(\d{6})",
        r"(\d{6})\D{0,80}(?:code|验证码|驗證碼|確認コード|認証コード)",
    )
    for pat in patterns:
        matches = re.findall(pat, clean, flags=re.IGNORECASE)
        matches = [m for m in matches if m not in noise]
        if matches:
            return matches[-1]

    # OpenAI 临时代码邮件：清理噪声后最后一个业务 6 位数最稳定。
    if any(h in subject_l for h in _YANGYANG_OPENAI_SUBJECT_HINTS) or "openai" in lower or "chatgpt" in lower:
        return candidates[-1]

    return _extract_code(clean)


def _parse_yangyang_code_url(code_url: str) -> tuple[str, str, str] | None:
    """
    解析 yangyang.website 这类邮箱页面：
        /messages/{token}/{email}
    返回 (origin, token, email)。
    """
    try:
        parsed = urlparse(code_url)
    except Exception:
        return None
    m = _YANGYANG_MESSAGES_RE.search(parsed.path or "")
    if not m:
        return None
    origin = urlunparse((parsed.scheme or "http", parsed.netloc, "", "", "", ""))
    token = unquote(m.group(1))
    email = unquote(m.group(2))
    if not origin or not token or not email:
        return None
    return origin.rstrip("/"), token, email


def _parse_zhangbinbin_code_url(code_url: str) -> tuple[str, str, str] | None:
    """解析 mail.zhangbinbin.edu.kg 的公开邮箱页面 URL。

    页面地址是 ``/mail/{email}/{token}``，真正返回最新邮件 JSON 的接口是
    ``/openapi/mail/{email}/{token}/latest``。历史导入里也可能已经保存了
    ``/openapi/mail/.../latest``，这里统一归一化。
    返回 (origin, email, token)。
    """
    try:
        parsed = urlparse(code_url)
    except Exception:
        return None
    hostname = (parsed.hostname or "").lower()
    if hostname != _ZHANGBINBIN_HOST and hostname not in _ZHANGBINBIN_LOCAL_HOSTS:
        return None
    m = _ZHANGBINBIN_MAIL_RE.fullmatch(parsed.path or "")
    if not m:
        m = _ZHANGBINBIN_OPENAPI_RE.fullmatch(parsed.path or "")
    if not m:
        return None
    email = unquote(m.group(1))
    token = unquote(m.group(2))
    origin = urlunparse((parsed.scheme or "https", parsed.netloc, "", "", "", ""))
    if not origin or not email or not token:
        return None
    return origin.rstrip("/"), email, token


def _zhangbinbin_latest_api_url(code_url: str) -> str | None:
    parsed = _parse_zhangbinbin_code_url(code_url)
    if not parsed:
        return None
    origin, email, token = parsed
    return f"{origin}/openapi/mail/{quote(email, safe='')}/{quote(token, safe='')}/latest"


def _response_text_utf8(resp, fallback: str = "") -> str:
    """优先按 UTF-8 解响应体，避免 requests 按 ISO-8859-1 把中文错误打成乱码。"""
    content = getattr(resp, "content", None)
    if isinstance(content, (bytes, bytearray)) and content:
        try:
            return bytes(content).decode("utf-8", errors="replace")
        except Exception:
            pass
    return fallback or str(getattr(resp, "text", "") or "")


def _zhangbinbin_error_message(resp, text: str = "") -> str:
    """提取 zhangbinbin latest API 的错误信息，隐藏敏感 URL/token。"""
    body = _response_text_utf8(resp, text).strip()
    if not body:
        return f"HTTP {getattr(resp, 'status_code', '-')}"
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            msg = (
                data.get("error")
                or data.get("message")
                or data.get("msg")
                or data.get("detail")
            )
            if msg:
                return str(msg)
    except Exception:
        pass
    return re.sub(r"\s+", " ", body)[:180]


def _parse_yangyang_ts(value: str | None) -> float | None:
    if not value:
        return None
    raw = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw[:19], fmt).timestamp()
        except Exception:
            pass
    return None


def _parse_generic_api_ts(value) -> float | None:
    """解析通用 API 返回的时间字段，兼容 ISO8601/Z 和常见本地时间格式。"""
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    # 数字时间戳：秒 / 毫秒
    if re.fullmatch(r"\d+(?:\.\d+)?", raw):
        try:
            ts = float(raw)
            return ts / 1000.0 if ts > 10_000_000_000 else ts
        except Exception:
            return None
    # ISO8601: 2026-08-05T01:10:17.000Z
    try:
        iso = raw
        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            return dt.timestamp()
        return dt.timestamp()
    except Exception:
        pass
    # 常见字符串格式
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw[:19], fmt).timestamp()
        except Exception:
            pass
    return None


def _is_structured_code_response(text: str) -> bool:
    """True 表示响应是带 code/OTP 字段的 JSON，即使该码因时间戳过旧被过滤。"""
    try:
        data = json.loads(text)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    nested = data.get("message") if isinstance(data.get("message"), dict) else {}
    return any(data.get(k) is not None for k in ("code", "otp", "verification_code", "verificationCode", "email_code", "emailCode")) or nested.get("code") is not None


def _extract_structured_api_code(text: str, after_ts: float | None = None) -> tuple[str, dict] | None:
    """
    兼容 newzoe 这类直接返回 JSON 的取码接口：
      {"code":"784207","from":"...","subject":"Your temporary ChatGPT login code","time":"2026-08-05T01:10:17.000Z"}

    如果响应里有 time/date/received_at，会按 after_ts 过滤旧码，避免拿到上一次缓存验证码。
    """
    if not text:
        return None
    try:
        data = json.loads(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    # mail.zhangbinbin.edu.kg 返回 {email, message: {code, receivedAt, ...}}；
    # 其它供应商仍然使用顶层字段，保持兼容。
    nested_message = data.get("message") if isinstance(data.get("message"), dict) else {}

    # 常见字段优先级：code / otp / verification_code；没有再回退从拉平文本提取。
    raw_code = (
        data.get("code")
        or data.get("otp")
        or data.get("verification_code")
        or data.get("verificationCode")
        or data.get("email_code")
        or data.get("emailCode")
        or nested_message.get("code")
    )
    code = None
    if raw_code is not None:
        m = _CODE_REGEX.search(str(raw_code))
        if m:
            code = m.group(1)
    if not code:
        code = _extract_code(_flatten_json(data))
    if not code:
        return None

    ts_raw = (
        data.get("time")
        or data.get("date")
        or data.get("received_at")
        or data.get("receivedAt")
        or data.get("created_at")
        or data.get("createdAt")
        or data.get("timestamp")
        or nested_message.get("receivedAt")
        or nested_message.get("received_at")
    )
    msg_ts = _parse_generic_api_ts(ts_raw)
    if after_ts and msg_ts and msg_ts + 2 < after_ts:
        logger.debug(
            "[GenericAPI] structured API 跳过旧验证码: code=%s ts=%s after=%s subject=%r",
            code,
            ts_raw,
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
            str(data.get("subject") or nested_message.get("subject") or "")[:80],
        )
        return None

    return code, {
        "source": "structured_api",
        "received_at": ts_raw,
        "msg_ts": msg_ts,
        "subject": data.get("subject") or nested_message.get("subject"),
        "from": (
            data.get("from")
            or data.get("fromAddress")
            or data.get("sender")
            or nested_message.get("from")
            or nested_message.get("sender")
        ),
    }


def _fetch_yangyang_otp(
    session: requests.Session,
    code_url: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """从 yangyang 邮箱页面的列表 API + 详情 API 中抽取最新 6 位验证码。"""
    parsed = _parse_yangyang_code_url(code_url)
    if not parsed:
        return None
    origin, token, email = parsed
    token_q = quote(token, safe="")
    email_q = quote(email, safe="@._+-")
    api_url = f"{origin}/api/messages/{token_q}/{email_q}"

    items: list[dict] = []
    cursor: str | None = None
    # 一般第一页足够；保守支持最多翻 5 页。
    for _ in range(5):
        url = api_url if not cursor else f"{api_url}?cursor={quote(str(cursor), safe='')}"
        resp = session.get(url, headers={**headers, "Accept": "application/json"}, timeout=20, verify=False)
        if resp.status_code != 200:
            if resp.status_code == 404:
                # 兼容 mail.ai1998.xyz 这类同样是 /messages/{token}/{email}，
                # 但没有 /api/messages，邮件直接内嵌在 HTML 页面中的实现。
                return _fetch_inline_messages_page_otp(
                    session=session,
                    code_url=code_url,
                    headers=headers,
                    after_ts=after_ts,
                )
            logger.debug(f"[GenericAPI] yangyang 邮件列表 HTTP {resp.status_code}: {resp.text[:160]}")
            return None
        data = resp.json()
        page_items = data.get("items") or []
        if isinstance(page_items, list):
            items.extend([x for x in page_items if isinstance(x, dict)])
        if not data.get("has_more") or not data.get("next_cursor"):
            break
        cursor = str(data.get("next_cursor"))

    # API 默认新邮件在前；再次按时间倒序，尽量取最新验证码。
    items.sort(key=lambda x: _parse_yangyang_ts(x.get("received_at") or x.get("receivedAt")) or 0, reverse=True)
    for item in items:
        msg_ts_raw = item.get("received_at") or item.get("receivedAt")
        msg_ts = _parse_yangyang_ts(msg_ts_raw)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            logger.debug(
                "[GenericAPI] yangyang 跳过旧邮件: id=%s ts=%s after=%s subject=%r",
                item.get("id"), msg_ts_raw, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
                item.get("subject") or "",
            )
            continue
        msg_id = item.get("id")
        if not msg_id:
            continue
        detail_url = f"{origin}/message/{quote(str(msg_id), safe='')}/{token_q}/{email_q}"
        try:
            detail_resp = session.get(detail_url, headers={**headers, "Accept": "application/json"}, timeout=20, verify=False)
            if detail_resp.status_code != 200:
                continue
            detail = detail_resp.json()
        except Exception as exc:
            logger.debug(f"[GenericAPI] yangyang 邮件详情读取失败: {type(exc).__name__}: {exc}")
            continue

        raw_body = str(detail.get("body") or "")
        body = _decode_data_uri(raw_body)
        subject = str(detail.get("subject") or item.get("subject") or "")
        text = "\n".join([
            subject,
            str(detail.get("fromAddress") or item.get("from_address") or ""),
            str(detail.get("receivedAt") or item.get("received_at") or ""),
            body,
        ])
        code = _extract_yangyang_openai_code(subject, body)
        if code:
            logger.info(
                f"[GenericAPI] yangyang 页面提取到 OTP={code}, "
                f"mail_id={msg_id}, ts={detail.get('receivedAt') or item.get('received_at')}, subject={subject[:80]!r}"
            )
            return code, {
                "mail_id": msg_id,
                "received_at": detail.get("receivedAt") or item.get("received_at"),
                "subject": subject,
                "msg_ts": msg_ts,
            }
    return None


def _strip_html_fragment(value: str) -> str:
    value = str(value or "")
    value = re.sub(r"<br\s*/?>", "\n", value, flags=re.IGNORECASE)
    value = re.sub(r"<[^>]+>", " ", value)
    value = html_lib.unescape(value)
    value = re.sub(r"[ \t\r\f\v]+", " ", value)
    value = re.sub(r"\n\s+", "\n", value)
    return value.strip()


def _fetch_inline_messages_page_otp(
    *,
    session: requests.Session,
    code_url: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """解析无 JSON API、直接把邮件卡片渲染在 HTML 里的 /messages 页面。"""
    try:
        resp = session.get(
            code_url,
            headers={**headers, "Accept": "text/html,application/xhtml+xml,text/plain,*/*"},
            timeout=20,
            verify=False,
        )
        if resp.status_code != 200:
            logger.debug("[GenericAPI] inline messages 页面 HTTP %s: %s", resp.status_code, (resp.text or "")[:160])
            return None
        html = resp.text or ""
    except Exception as exc:
        logger.debug("[GenericAPI] inline messages 页面读取失败: %s: %s", type(exc).__name__, exc)
        return None

    cards = re.findall(r"<article\b[^>]*class=[\"'][^\"']*mail-card[^\"']*[\"'][^>]*>(.*?)</article>", html, flags=re.DOTALL | re.IGNORECASE)
    # 没有 article 时退一步按 details 分块，避免 class 名细微变化。
    if not cards:
        cards = re.findall(r"<details\b[^>]*>(.*?)</details>", html, flags=re.DOTALL | re.IGNORECASE)

    items: list[dict] = []
    for idx, card in enumerate(cards):
        subject_m = re.search(r"<span\b[^>]*class=[\"'][^\"']*subject[^\"']*[\"'][^>]*>(.*?)</span>", card, flags=re.DOTALL | re.IGNORECASE)
        date_m = re.search(r"<span\b[^>]*class=[\"'][^\"']*date[^\"']*[\"'][^>]*>(.*?)</span>", card, flags=re.DOTALL | re.IGNORECASE)
        from_m = re.search(r"<div\b[^>]*class=[\"'][^\"']*meta[^\"']*[\"'][^>]*>(.*?)</div>", card, flags=re.DOTALL | re.IGNORECASE)
        body_m = re.search(r"<pre\b[^>]*class=[\"'][^\"']*body[^\"']*[\"'][^>]*>(.*?)</pre>", card, flags=re.DOTALL | re.IGNORECASE)
        if not body_m:
            body_m = re.search(r"<div\b[^>]*class=[\"'][^\"']*body[^\"']*[\"'][^>]*>(.*?)</div>", card, flags=re.DOTALL | re.IGNORECASE)

        subject = _strip_html_fragment(subject_m.group(1) if subject_m else "")
        received_at = _strip_html_fragment(date_m.group(1) if date_m else "")
        from_addr = _strip_html_fragment(from_m.group(1) if from_m else "")
        body = _strip_html_fragment(body_m.group(1) if body_m else card)
        msg_ts = _parse_yangyang_ts(received_at)
        items.append({
            "mail_id": f"inline-{idx}",
            "subject": subject,
            "received_at": received_at,
            "from": from_addr,
            "body": body,
            "msg_ts": msg_ts or 0.0,
        })

    items.sort(key=lambda x: float(x.get("msg_ts") or 0.0), reverse=True)
    for item in items:
        msg_ts = float(item.get("msg_ts") or 0.0)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            logger.debug(
                "[GenericAPI] inline messages 跳过旧邮件: id=%s ts=%s after=%s subject=%r",
                item.get("mail_id"), item.get("received_at"),
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
                item.get("subject") or "",
            )
            continue
        code = _extract_yangyang_openai_code(str(item.get("subject") or ""), str(item.get("body") or ""))
        if code:
            logger.info(
                "[GenericAPI] inline messages 页面提取到 OTP=%s, mail_id=%s, ts=%s, subject=%r",
                code, item.get("mail_id"), item.get("received_at"), str(item.get("subject") or "")[:80],
            )
            return code, {
                "mail_id": item.get("mail_id"),
                "received_at": item.get("received_at"),
                "subject": item.get("subject"),
                "msg_ts": msg_ts,
            }
    return None


def pick_account() -> GenericApiEmailAccount:
    """直接从 SQLite 邮箱库领取一个可用通用 API 邮箱。"""
    from core.db import claim_next_generic_api_email, generic_api_email_pool_summary

    row = claim_next_generic_api_email()
    if row is None:
        summary = generic_api_email_pool_summary()
        raise GenericApiMailError(
            f"通用 API 邮箱池没有可用账号: {summary}. 请在 WebUI 邮箱池导入：邮箱----取码地址"
        )
    account = GenericApiEmailAccount(email=row["email"], code_url=row["code_url"])
    _CONTEXT_CACHE[account.email] = account
    logger.info(f"[GenericAPI] 选中邮箱: {account.email}（DB id={row.get('id')}）")
    return account


def import_from_file(path: str | Path | None = None) -> tuple[int, int]:
    """从文本文件导入通用 API 邮箱，每行：email----code_url 或 email====code_url。"""
    from core.db import import_generic_api_emails
    p = Path(path) if path else _ACCOUNTS_FILE
    if not p.is_absolute():
        p = _PROJECT_ROOT / p
    if not p.exists():
        return 0, 0
    records = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("----") if "----" in line else line.split("====")
        parts = [x.strip() for x in parts]
        if len(parts) < 2:
            continue
        records.append({"email": parts[0], "code_url": parts[1]})
    return import_generic_api_emails(records)


def get_account_context(email: str) -> GenericApiEmailAccount | None:
    if email in _CONTEXT_CACHE:
        return _CONTEXT_CACHE[email]
    from core.db import get_generic_api_email_by_email
    row = get_generic_api_email_by_email(email)
    if row is None:
        return None
    account = GenericApiEmailAccount(email=row["email"], code_url=row["code_url"])
    _CONTEXT_CACHE[email] = account
    return account


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    from core.db import release_generic_api_email
    release_generic_api_email(email, status=status, note=note)
    _CONTEXT_CACHE.pop(email, None)


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
    exclude_codes: set[str] | None = None,
) -> str:
    """
    轮询该邮箱配置的 code_url，直到提取到 6 位验证码或超时。

    settle 机制：首次拿到验证码后不立刻返回，而是继续等 OTP_SETTLE_SECONDS 秒。
    如果期间取码地址返回了不同验证码，则替换候选并重置 settle 倒计时；
    连续 settle 秒没有变化后才返回，避免取到接口缓存中的旧码。
    """
    account = get_account_context(email)
    if account is None:
        raise GenericApiMailError(f"通用 API 邮箱不存在或未导入: {email}")
    from core.db import get_generic_api_email_by_email
    pool_row = get_generic_api_email_by_email(email)
    if pool_row and pool_row.get("status") == "mail_deleted":
        # 已确认删除的隐藏邮箱不会再收到 OTP，避免每次查活重复轮询和重发。
        raise GenericApiPickupInvalidError("取件地址已失效：隐藏邮箱已删除，无法接收验证码")

    deadline = time.time() + (max_wait or _email_cfg.OTP_MAX_WAIT)
    interval = poll_interval or _email_cfg.OTP_POLL_INTERVAL
    settle = settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS
    headers = {
        "Accept": "application/json,text/plain,*/*",
        "User-Agent": "Mozilla/5.0 (compatible; gpt-register/1.0)",
        "Cache-Control": "no-cache, no-store, max-age=0",
        "Pragma": "no-cache",
    }
    last_error = ""
    best_otp: str | None = None
    best_seen_at: float = 0.0
    settle_until: float | None = None
    excluded = {str(code).strip() for code in (exclude_codes or set()) if str(code).strip()}
    consecutive_provider_5xx = 0
    logger.info(
        f"[GenericAPI] 开始轮询取码地址: {email}，"
        f"最长 {max_wait or _email_cfg.OTP_MAX_WAIT}s, settle={settle}s"
    )
    is_yangyang = _parse_yangyang_code_url(account.code_url) is not None
    zhangbinbin_api_url = _zhangbinbin_latest_api_url(account.code_url)
    if zhangbinbin_api_url:
        logger.info("[GenericAPI] 识别到 zhangbinbin 邮箱页面，切换到 latest JSON API")

    attempt = 0
    while time.time() < deadline:
        attempt += 1
        sleep_for = interval
        try:
            session = requests.Session()
            # yangyang 使用列表/详情 API；zhangbinbin 的页面 URL 则转换为 latest JSON API。
            if is_yangyang:
                poll_url = account.code_url
            elif zhangbinbin_api_url:
                poll_url = _cache_busted_url(zhangbinbin_api_url, attempt)
                # 自有 zhangbinbin 取件服务支持按需 IMAP 同步；注册等 OTP 时
                # 主动触发并短暂等待，避免后台同步/代理抖动导致验证码晚几十分钟入库。
                poll_url = _append_query_params(poll_url, {"forceSync": "1", "waitMs": "8000"})
            else:
                poll_url = _cache_busted_url(account.code_url, attempt)
            yy_result = _fetch_yangyang_otp(session, poll_url, headers, after_ts=after_ts) if is_yangyang else None
            if yy_result:
                code, yy_meta = yy_result
                now_seen = time.time()
                if not best_otp:
                    best_otp = code
                    best_seen_at = now_seen
                    settle_until = now_seen + settle
                    logger.info(
                        f"[GenericAPI] 首次锁定 OTP={code}, source=yangyang mail_id={yy_meta.get('mail_id')} ts={yy_meta.get('received_at')}, "
                        f"等 {settle}s 看取码接口是否出现更新验证码..."
                    )
                elif code != best_otp:
                    logger.info(
                        f"[GenericAPI] 发现更新 OTP={code}, source=yangyang mail_id={yy_meta.get('mail_id')} ts={yy_meta.get('received_at')}，"
                        f"替换之前的 {best_otp}, 重置 settle 计时"
                    )
                    best_otp = code
                    best_seen_at = now_seen
                    settle_until = now_seen + settle
                else:
                    logger.debug(f"[GenericAPI] 取码接口仍返回候选 OTP={best_otp}")
                resp = None
                text = ""
            else:
                if is_yangyang:
                    last_error = "yangyang 列表中尚未出现 after_ts 之后的新验证码邮件"
                    resp = None
                    text = ""
                else:
                    resp = _get_with_connection_fallback(
                        session, poll_url, headers=headers, timeout=20,
                    )
                    text = resp.text or ""
            if resp is None:
                pass
            elif resp.status_code == 200:
                consecutive_provider_5xx = 0
                structured = _extract_structured_api_code(text, after_ts=after_ts)
                structured_meta = structured[1] if structured else {}
                has_structured_code = _is_structured_code_response(text)
                # structured JSON 中的旧验证码被 after_ts 过滤后，不能再对原始 JSON
                # 做 _extract_code 回退，否则会把同一条过期码重新捞回来。
                code = structured[0] if structured else (None if has_structured_code else _extract_code(text))
                if code is None and has_structured_code:
                    last_error = "取码接口仅返回 after_ts 之前的旧验证码，等待新邮件"
                if code and code in excluded:
                    last_error = "取码接口仍返回已提交过的旧验证码"
                    code = None
                if code:
                    now_seen = time.time()
                    if not best_otp:
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                        if structured_meta:
                            logger.info(
                                f"[GenericAPI] 首次锁定 OTP={code}, source=structured_api "
                                f"ts={structured_meta.get('received_at')} subject={str(structured_meta.get('subject') or '')[:80]!r}, "
                                f"等 {settle}s 看取码接口是否出现更新验证码..."
                            )
                        else:
                            logger.info(
                                f"[GenericAPI] 首次锁定 OTP={code}, "
                                f"等 {settle}s 看取码接口是否出现更新验证码..."
                            )
                    elif code != best_otp:
                        if structured_meta:
                            logger.info(
                                f"[GenericAPI] 发现更新 OTP={code}, source=structured_api "
                                f"ts={structured_meta.get('received_at')} subject={str(structured_meta.get('subject') or '')[:80]!r}，"
                                f"替换之前的 {best_otp}, 重置 settle 计时"
                            )
                        else:
                            logger.info(
                                f"[GenericAPI] 发现更新 OTP={code}，"
                                f"替换之前的 {best_otp}, 重置 settle 计时"
                            )
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                    else:
                        logger.debug(f"[GenericAPI] 取码接口仍返回候选 OTP={best_otp}")
                elif not has_structured_code:
                    last_error = f"HTTP 200 但未提取到 6 位验证码，响应预览: {text[:160]}"
            elif zhangbinbin_api_url and resp.status_code == 404:
                # 该站点的页面路由仍可能返回 200，但对应邮箱 token 已失效时
                # latest API 会直接返回 404。继续轮询/重发 OTP 都没有意义，
                # 立即标记邮箱池素材失败，避免查活时同一个坏 token 连续重试三轮。
                detail = _zhangbinbin_error_message(resp, text)
                note = f"zhangbinbin 取件地址无效: {detail}"
                try:
                    release_account(email, status="mail_deleted", note=note)
                except Exception as mark_exc:
                    logger.warning("[GenericAPI] 标记取件地址失败状态异常：%s", mark_exc)
                raise GenericApiPickupInvalidError(
                    "zhangbinbin 取件地址里的邮箱/密钥无效，无法取码；"
                    f"请重新导入新的邮箱+取件地址（{detail}）"
                )
            elif zhangbinbin_api_url and resp.status_code == 530:
                # Cloudflare Tunnel 1033 是上游隧道暂时断开，不代表邮箱+取件地址失效。
                # 尊重服务端 retry_after，避免 3 秒一轮把短暂故障刷成整次注册失败。
                retry_after = None
                error_code = ""
                retryable = None
                try:
                    error_body = resp.json()
                    if isinstance(error_body, dict):
                        error_code = str(error_body.get("error_code") or "")
                        retryable = error_body.get("retryable")
                        raw_retry_after = error_body.get("retry_after")
                        if raw_retry_after is not None:
                            retry_after = max(1, min(180, int(float(raw_retry_after))))
                except Exception:
                    pass
                suffix = f"/{error_code}" if error_code else ""
                last_error = (
                    f"HTTP 530{suffix}：邮箱服务 Cloudflare Tunnel 暂时不可达"
                    + (f"，建议 {retry_after}s 后重试" if retry_after else "")
                )
                if retry_after:
                    sleep_for = max(interval, retry_after)
                if attempt == 1 or attempt % 5 == 0:
                    logger.warning(
                        "[GenericAPI] 邮箱服务暂时不可达（HTTP 530%s, retryable=%s），%ss 后重试",
                        suffix,
                        retryable,
                        sleep_for,
                    )
            elif zhangbinbin_api_url and resp.status_code in (502, 520, 521, 522, 523, 524):
                # Cloudflare 502/52x 通常是取件站点源站/隧道挂了，继续按 3s 轮询只会
                # 浪费整轮注册时间。连续几次确认后尽快失败，让上层/用户切换邮箱源。
                consecutive_provider_5xx += 1
                last_error = (
                    f"HTTP {resp.status_code}：zhangbinbin 取件服务当前不可用"
                    f"（连续 {consecutive_provider_5xx} 次）"
                )
                sleep_for = max(interval, 10)
                logger.warning("[GenericAPI] %s，%ss 后复查", last_error, sleep_for)
                if consecutive_provider_5xx >= 3:
                    raise GenericApiMailError(
                        f"zhangbinbin 取件服务疑似挂了：{last_error}；"
                        "请稍后重试，或切换 EMAIL_SOURCE / 导入其它取件服务邮箱"
                    )
            else:
                consecutive_provider_5xx = 0
                last_error = f"HTTP {resp.status_code}: {text[:160]}"
        except GenericApiMailError:
            raise
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        now = time.time()
        if best_otp and settle_until is not None and now >= settle_until:
            logger.info(
                f"[GenericAPI] settle 完成，返回 OTP={best_otp}, "
                f"候选锁定时间={time.strftime('%H:%M:%S', time.localtime(best_seen_at))}"
            )
            return best_otp

        # int() 会把 (0, 1) 秒截断成 0；旧代码随后 sleep(0) 并继续 while，
        # 在 deadline 边界产生高频空轮询，看起来像“卡取件”。到期必须立即退出。
        remaining_seconds = deadline - now
        if remaining_seconds <= 0:
            break
        remaining = max(1, int(remaining_seconds))
        if best_otp and settle_until is not None:
            logger.info(
                f"[GenericAPI] 已锁定候选 OTP={best_otp}，等 settle 中"
                f"（剩余 settle ~{max(0, int(settle_until - now))}s, 总剩余 {remaining}s）..."
            )
        else:
            logger.info(
                f"[GenericAPI] 暂未从取码接口拿到验证码，"
                f"{interval}s 后重试（剩余 {remaining}s）..."
            )
        time.sleep(min(sleep_for, remaining_seconds))

    if best_otp:
        logger.warning(f"[GenericAPI] 总超时但已有候选，返回 OTP={best_otp}")
        return best_otp

    raise GenericApiMailError(f"等待通用 API 验证码超时: {email}; {last_error}")
