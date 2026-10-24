# -*- coding: utf-8 -*-
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import requests

from core import account_usage, db
from webui.app import create_app


class AccountUsageTests(unittest.TestCase):
    def test_normalizes_only_quota_fields(self):
        response = Mock(status_code=200)
        response.json.return_value = {
            "email": "A@example.com", "user_id": "private", "plan_type": "plus",
            "rate_limit": {
                "allowed": True, "limit_reached": False,
                "primary_window": {"used_percent": 25, "limit_window_seconds": 18000, "reset_at": 123},
                "secondary_window": {"used_percent": 50, "limit_window_seconds": 604800, "reset_at": 456},
            },
            "credits": {"balance": "0"},
        }
        with patch.object(account_usage.requests, "get", return_value=response) as get:
            result = account_usage.fetch_account_usage("sample-token", expected_email="a@example.com")
        self.assertTrue(result["ok"])
        self.assertEqual(result["primary_window"]["used_percent"], 25)
        self.assertEqual(result["secondary_window"]["reset_at"], 456)
        self.assertNotIn("user_id", result)
        self.assertNotIn("email", result)
        self.assertNotIn("credits", result)
        self.assertEqual(get.call_args.kwargs["headers"]["Authorization"], "Bearer sample-token")

    def test_rejects_mismatched_account_and_401(self):
        response = Mock(status_code=200)
        response.json.return_value = {"email": "other@example.com", "rate_limit": {}}
        with patch.object(account_usage.requests, "get", return_value=response):
            result = account_usage.fetch_account_usage("sample-token", expected_email="a@example.com")
        self.assertFalse(result["ok"])
        self.assertIn("不一致", result["error"])
        with patch.object(account_usage.requests, "get", return_value=Mock(status_code=401)):
            result = account_usage.fetch_account_usage("sample-token")
        self.assertFalse(result["ok"])
        self.assertEqual(result["http_status"], 401)

    def test_retries_via_local_proxy_after_direct_timeout(self):
        response = Mock(status_code=200)
        response.json.return_value = {"rate_limit": {"allowed": True}}
        with patch.object(account_usage, "_fallback_proxy", return_value="http://127.0.0.1:7897"), \
             patch.object(account_usage.requests, "get", side_effect=[requests.ConnectTimeout(), response]) as get:
            result = account_usage.fetch_account_usage("sample-token")
        self.assertTrue(result["ok"])
        self.assertEqual(get.call_count, 2)
        self.assertEqual(get.call_args.kwargs["proxies"]["https"], "http://127.0.0.1:7897")

    def test_route_persists_snapshot_without_leaking_token(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            accounts_path = root / "accounts.json"
            accounts_path.write_text(json.dumps([{"id": 1, "email": "a@example.com", "access_token": "sample-token"}]), encoding="utf-8")
            with patch.object(db, "_ACCOUNTS_JSON", accounts_path), \
                 patch.object(db, "_LEGACY_ACCOUNTS_JSON", root / "legacy_accounts.json"), \
                 patch.object(db, "_ACCOUNTS_TXT", root / "accounts.txt"), \
                 patch.object(db, "_TOKENS_TXT", root / "tokens.txt"), \
                 patch.object(db, "_VIEWER_HTML", root / "viewer.html"):
                app = create_app(auth_code="test-secret")
                app.testing = True
                client = app.test_client()
                client.post("/login", data={"auth_code": "test-secret"})
                result = {
                    "ok": True, "checked_at": "2026-10-20T20:00:00", "plan_type": "plus",
                    "allowed": True, "limit_reached": False,
                    "primary_window": {"used_percent": 10, "reset_at": 123},
                    "secondary_window": {"used_percent": 20, "reset_at": 456},
                }
                with patch.object(account_usage, "fetch_account_usage", return_value=result) as fetch:
                    response = client.post("/api/accounts/1/usage-check", headers={"Accept-Encoding": "identity"})
                self.assertEqual(response.status_code, 200)
                self.assertNotIn("sample-token", response.get_data(as_text=True))
                fetch.assert_called_once_with("sample-token", expected_email="a@example.com")
                account = db.get_account(1)
                self.assertEqual(account["usage_primary_used_percent"], 10)
                self.assertEqual(account["usage_secondary_used_percent"], 20)


if __name__ == "__main__":
    unittest.main()
