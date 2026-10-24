# -*- coding: utf-8 -*-
import base64
import json
import unittest
from unittest.mock import patch

from core import generic_api_mail_client as client
from core.generic_api_mail_client import (
    _decode_data_uri,
    _extract_code,
    _extract_structured_api_code,
    _is_structured_code_response,
    _fetch_yangyang_otp,
    _parse_yangyang_code_url,
    _parse_zhangbinbin_code_url,
    _zhangbinbin_error_message,
    _zhangbinbin_latest_api_url,
)


class FakeResponse:
    def __init__(self, status_code=200, data=None, text=""):
        self.status_code = status_code
        self._data = data
        self.text = text
        self.content = text.encode("utf-8")

    def json(self):
        return self._data


class FakeSession:
    def __init__(self):
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        if "/api/messages/" in url:
            return FakeResponse(data={
                "items": [
                    {"id": 1, "subject": "旧码", "received_at": "2026-08-01 10:00:00"},
                    {"id": 2, "subject": "Your OpenAI code is 654321", "received_at": "2026-08-01 10:01:00"},
                ],
                "has_more": False,
            })
        if "/message/2/" in url:
            html = "<html><body>Your verification code is <b>654321</b></body></html>"
            body = "data:text/html;charset=utf-8;base64," + base64.b64encode(html.encode()).decode()
            return FakeResponse(data={"subject": "Your OpenAI code is 654321", "body": body, "receivedAt": "2026-08-01 10:01:00"})
        if "/message/1/" in url:
            return FakeResponse(data={"subject": "旧码", "body": "code 111111", "receivedAt": "2026-08-01 10:00:00"})
        return FakeResponse(status_code=404, text="not found")


class FakeInlineSession:
    def get(self, url, **kwargs):
        if "/api/messages/" in url:
            return FakeResponse(status_code=404, text="Not Found")
        return FakeResponse(text="""
        <article class="mail-card">
          <details open>
            <summary>
              <span class="subject">Your temporary ChatGPT verification code</span>
              <span class="date">2026-08-02 13:18:53</span>
            </summary>
            <div class="meta">发件人：otp@example.com</div>
            <pre class="body">Enter this temporary verification code to continue:

541409

Please ignore this email.</pre>
          </details>
        </article>
        """)


class GenericApiYangyangTests(unittest.TestCase):
    def test_parse_yangyang_url(self):
        self.assertEqual(
            _parse_yangyang_code_url("http://yangyang.website/messages/tok/a@icloud.com"),
            ("http://yangyang.website", "tok", "a@icloud.com"),
        )

    def test_decode_data_uri_base64(self):
        body = "data:text/html;base64," + base64.b64encode("验证码 123456".encode()).decode()
        self.assertIn("123456", _decode_data_uri(body))

    def test_fetch_yangyang_otp_uses_api_and_detail(self):
        result = _fetch_yangyang_otp(
            FakeSession(),
            "http://yangyang.website/messages/tok/a@icloud.com",
            {"User-Agent": "test"},
        )
        code, meta = result
        self.assertEqual(code, "654321")
        self.assertEqual(meta["mail_id"], 2)

    def test_fetch_yangyang_otp_respects_after_ts(self):
        import datetime
        after = datetime.datetime(2026, 8, 1, 10, 2, 0).timestamp()
        result = _fetch_yangyang_otp(
            FakeSession(),
            "http://yangyang.website/messages/tok/a@icloud.com",
            {"User-Agent": "test"},
            after_ts=after,
        )
        self.assertIsNone(result)

    def test_fetch_inline_messages_page_without_api(self):
        result = _fetch_yangyang_otp(
            FakeInlineSession(),
            "https://mail.ai1998.xyz/messages/tok/cookies-benzene.48%40icloud.com",
            {"User-Agent": "test"},
        )
        code, meta = result
        self.assertEqual(code, "541409")
        self.assertEqual(meta["mail_id"], "inline-0")

    def test_parse_zhangbinbin_page_url_to_latest_api(self):
        page_url = "https://mail.zhangbinbin.edu.kg/mail/a%40icloud.com/tok%2Fpart"
        self.assertEqual(
            _parse_zhangbinbin_code_url(page_url),
            ("https://mail.zhangbinbin.edu.kg", "a@icloud.com", "tok/part"),
        )
        self.assertEqual(
            _zhangbinbin_latest_api_url(page_url),
            "https://mail.zhangbinbin.edu.kg/openapi/mail/a%40icloud.com/tok%2Fpart/latest",
        )

    def test_parse_local_zhangbinbin_page_url_to_latest_api(self):
        page_url = "http://127.0.0.1:4173/mail/a%40icloud.com/tok%2Fpart"
        self.assertEqual(
            _parse_zhangbinbin_code_url(page_url),
            ("http://127.0.0.1:4173", "a@icloud.com", "tok/part"),
        )
        self.assertEqual(
            _zhangbinbin_latest_api_url(page_url),
            "http://127.0.0.1:4173/openapi/mail/a%40icloud.com/tok%2Fpart/latest",
        )

    def test_zhangbinbin_404_marks_bad_pickup_url(self):
        email = "bad@icloud.com"
        client._CONTEXT_CACHE[email] = client.GenericApiEmailAccount(
            email=email,
            code_url="https://mail.zhangbinbin.edu.kg/openapi/mail/bad%40icloud.com/token/latest",
        )
        response = FakeResponse(
            status_code=404,
            data={"error": "邮件地址或密钥无效"},
            text=json.dumps({"error": "邮件地址或密钥无效"}, ensure_ascii=False),
        )
        with patch("core.generic_api_mail_client._get_with_connection_fallback", return_value=response), \
             patch("core.generic_api_mail_client.release_account") as release_account:
            with self.assertRaises(client.GenericApiPickupInvalidError) as raised:
                client.fetch_latest_otp(email, max_wait=1, poll_interval=1, settle_seconds=0)
        release_account.assert_called_once()
        self.assertEqual(release_account.call_args.kwargs["status"], "mail_deleted")
        self.assertIn("邮件地址或密钥无效", str(raised.exception))
        client._CONTEXT_CACHE.pop(email, None)

    def test_mail_deleted_pool_row_fails_before_polling(self):
        email = "deleted@icloud.com"
        account = client.GenericApiEmailAccount(
            email=email,
            code_url="https://mail.zhangbinbin.edu.kg/mail/deleted%40icloud.com/token",
        )
        with patch.object(client, "get_account_context", return_value=account), \
             patch("core.db.get_generic_api_email_by_email", return_value={"status": "mail_deleted"}), \
             patch.object(client, "_get_with_connection_fallback") as fetch:
            with self.assertRaises(client.GenericApiPickupInvalidError) as raised:
                client.fetch_latest_otp(email, max_wait=1)
        self.assertIn("取件地址已失效", str(raised.exception))
        fetch.assert_not_called()

    def test_zhangbinbin_error_message_decodes_utf8_body(self):
        response = FakeResponse(
            status_code=404,
            text=json.dumps({"error": "邮件地址或密钥无效"}, ensure_ascii=False),
        )
        self.assertEqual(_zhangbinbin_error_message(response, response.text), "邮件地址或密钥无效")

    def test_extract_nested_zhangbinbin_message(self):
        result = _extract_structured_api_code(json.dumps({
            "email": "a@icloud.com",
            "message": {
                "code": "654321",
                "subject": "Your temporary ChatGPT login code",
                "receivedAt": "2026-09-03T10:42:25.000Z",
            },
        }))
        self.assertIsNotNone(result)
        code, meta = result
        self.assertEqual(code, "654321")
        self.assertEqual(meta["subject"], "Your temporary ChatGPT login code")

    def test_extract_vietnamese_zhangbinbin_message(self):
        payload = json.dumps({
            "email": "a@icloud.com",
            "message": {
                "subject": "Mã xác minh tạm thời của bạn cho ChatGPT",
                "sender": "ChatGPT <noreply@example.com>",
                "code": "180486",
                "preview": "Nhập mã xác minh tạm thời này để tiếp tục: 180486",
                "receivedAt": "2026-09-19T01:37:05.000Z",
            },
        }, ensure_ascii=False)
        result = _extract_structured_api_code(payload)
        self.assertIsNotNone(result)
        code, meta = result
        self.assertEqual(code, "180486")
        self.assertEqual(meta["subject"], "Mã xác minh tạm thời của bạn cho ChatGPT")
        self.assertEqual(_extract_code(payload), "180486")

    def test_structured_old_code_is_detected_after_timestamp_filter(self):
        import datetime
        payload = json.dumps({
            "email": "a@icloud.com",
            "message": {
                "subject": "Mã xác minh tạm thời của bạn cho ChatGPT",
                "code": "180486",
                "receivedAt": "2026-09-19T01:37:05.000Z",
            },
        }, ensure_ascii=False)
        after = datetime.datetime(2026, 10, 8, 0, 47, 0).timestamp()
        self.assertIsNone(_extract_structured_api_code(payload, after_ts=after))
        self.assertTrue(_is_structured_code_response(payload))



if __name__ == "__main__":
    unittest.main()
