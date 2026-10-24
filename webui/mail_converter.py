# -*- coding: utf-8 -*-
"""本地邮箱池取件地址转换工具。只做文本转换，不请求远端接口。"""
from __future__ import annotations

import re
from urllib.parse import quote, unquote, urlparse, urlunparse

HOST = "mail.zhangbinbin.edu.kg"
PAGE_RE = re.compile(
    r"https?://mail\.zhangbinbin\.edu\.kg/mail/[^\s<>()\[\]]+",
    re.IGNORECASE,
)


def convert_url(page_url: str) -> str | None:
    try:
        parsed = urlparse(page_url.rstrip(".,;"))
    except Exception:
        return None
    if (parsed.hostname or "").lower() != HOST:
        return None
    parts = (parsed.path or "").split("/")
    if len(parts) != 4 or parts[1].lower() != "mail" or not parts[2] or not parts[3]:
        return None
    email = unquote(parts[2])
    token = unquote(parts[3])
    origin = urlunparse((parsed.scheme or "https", parsed.netloc, "", "", "", ""))
    return f"{origin}/openapi/mail/{quote(email, safe='')}/{quote(token, safe='')}/latest"


def convert_text(text: str) -> dict:
    """转换文本，保留原有行和 Markdown 包装，返回结果及统计。"""
    lines = []
    counts = {"converted": 0, "skipped": 0, "invalid": 0}
    for line in str(text or "").splitlines(keepends=True):
        match = PAGE_RE.search(line)
        if not match:
            lines.append(line)
            counts["skipped"] += 1
            continue
        new_url = convert_url(match.group(0))
        if not new_url:
            lines.append(line)
            counts["invalid"] += 1
            continue
        lines.append(line[:match.start()] + new_url + line[match.end():])
        counts["converted"] += 1
    return {"text": "".join(lines), "counts": counts}
