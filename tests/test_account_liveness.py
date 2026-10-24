# -*- coding: utf-8 -*-
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import core.account_liveness as liveness
import core.live_check_service as live_service


class _DummyHttpSession:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _DummyBrowserSession:
    created = []

    def __init__(self, proxy=None, **kwargs):
        self.proxy = proxy
        self.received_proxy = proxy
        self.device_id = "device-test"
        self.session = _DummyHttpSession()
        self.blocked_until = 0.0
        self.blocked_reason = ""
        self.created.append(self)
        self.kwargs = kwargs

    def fingerprint_summary(self):
        return {
            "proxy": self.proxy or "",
            "user_agent": "test-agent",
            "accept_language": "en-US",
            "timezone_iana": "UTC",
            "timezone_offset_minutes": 0,
            "screen_width": 1440,
            "screen_height": 900,
            "device_pixel_ratio": 2,
            "hardware_concurrency": 8,
            "device_memory": 8,
            "geo_country": "US",
            "geo_city": "Test",
        }

    def fingerprint_summary_text(self):
        return "test-fingerprint"

    def reset_circuit_breaker(self):
        self.blocked_until = 0.0
        self.blocked_reason = ""


class _DummyQueueSlot:
    def __init__(self):
        self.released = False

    def release(self):
        self.released = True


class AccountLivenessTests(unittest.TestCase):
    def setUp(self):
        _DummyBrowserSession.created = []

    def test_browser_get_retries_after_navigation_destroys_context(self):
        page = Mock()
        page.evaluate.side_effect = [
            RuntimeError("Page.evaluate: Execution context was destroyed, most likely because of a navigation."),
            {"status": 200, "text": "{}"},
        ]
        with patch.object(liveness.time, "sleep"):
            result = liveness._browser_fetch(page, "https://chatgpt.com/api/auth/csrf")
        self.assertEqual(result["status"], 200)
        self.assertEqual(page.evaluate.call_count, 2)
        page.wait_for_load_state.assert_called_once_with("domcontentloaded", timeout=15000)

    def test_browser_post_is_not_replayed_after_navigation(self):
        page = Mock()
        page.evaluate.side_effect = RuntimeError("Page.evaluate: Execution context was destroyed")
        with self.assertRaisesRegex(RuntimeError, "Execution context was destroyed"):
            liveness._browser_fetch(page, "https://chatgpt.com/api/auth/signin/openai", method="POST", body="x=1")
        page.evaluate.assert_called_once()
        page.wait_for_load_state.assert_not_called()

    def test_preflight_preserves_explicit_direct_route_and_skips_providers(self):
        with patch.object(liveness, "BrowserSession", _DummyBrowserSession), \
             patch.object(liveness, "get_csrf_token", return_value="csrf"), \
             patch.object(liveness, "signin_openai", return_value="https://auth.example/authorize"):
            session, authorize_url = liveness._network_preflight_with_retry(
                "user@example.com", "", max_attempts=1
            )

        self.assertEqual(session.proxy, "")
        self.assertEqual(authorize_url, "https://auth.example/authorize")
        self.assertEqual(session.kwargs["fingerprint_seed"], "account:user@example.com")

    def test_preflight_retries_with_new_session_when_csrf_is_blocked(self):
        csrf_errors = [RuntimeError("HTTP Error 403"), "csrf"]
        with patch.object(liveness, "BrowserSession", _DummyBrowserSession), \
             patch.object(liveness, "get_csrf_token", side_effect=csrf_errors), \
             patch.object(liveness, "signin_openai", return_value="authorize"), \
             patch.object(liveness.time, "sleep"):
            session, _ = liveness._network_preflight_with_retry(
                "user@example.com", None, max_attempts=2
            )

        self.assertIs(_DummyBrowserSession.created[-1], session)
        self.assertEqual(len(_DummyBrowserSession.created), 2)
        self.assertTrue(_DummyBrowserSession.created[0].session.closed)
        # None means each attempt may reselect a proxy from the configured pool.
        self.assertIsNone(_DummyBrowserSession.created[0].received_proxy)
        self.assertIsNone(_DummyBrowserSession.created[1].received_proxy)

    def test_reauth_otp_dead_account_error_is_not_retried(self):
        response = SimpleNamespace(
            status_code=403,
            text='{"error":{"code":"account_deactivated"}}',
        )
        error = RuntimeError("HTTP Error 403")
        error.response = response
        session = _DummyBrowserSession(proxy="proxy")

        with patch.object(liveness, "_validate_reauth_otp", side_effect=error), \
             patch.object(liveness, "wait_for_otp", return_value="123456"):
            with self.assertRaises(liveness.AccountUnusableError) as ctx:
                liveness._validate_reauth_with_retry(session, "user@example.com", 1.0)

        self.assertEqual(ctx.exception.error_code, "account_deactivated")

    def test_existing_access_token_uses_reauth_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _DummyBrowserSession(proxy="")
            with patch.object(liveness, "_LOG_DIR", Path(tmp)), \
                 patch.object(liveness, "_stored_access_token", return_value="old-token"), \
                 patch.object(liveness, "BrowserSession", return_value=session), \
                 patch.object(liveness, "_check_stored_access_token", return_value=None), \
                 patch.object(liveness, "_warm_authenticated_session") as warm, \
                 patch.object(liveness, "human_delay"), \
                 patch.object(liveness, "_login_via_reauth", return_value={
                     "accessToken": "new-token",
                     "user": {"id": "user-1"},
                     "account": {"planType": "free"},
                 }) as reauth:
                result = liveness.check_account_liveness("user@example.com", proxy="")

        self.assertTrue(result["ok"])
        self.assertEqual(result["access_token"], "new-token")
        warm.assert_called_once_with(session, "old-token")
        reauth.assert_called_once()
        self.assertTrue(session.session.closed)

    def test_valid_existing_access_token_skips_reauth_even_with_totp(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = _DummyBrowserSession(proxy="")
            with patch.object(liveness, "_LOG_DIR", Path(tmp)), \
                 patch.object(liveness, "_stored_access_token", return_value="old-token"), \
                 patch.object(liveness, "BrowserSession", return_value=session), \
                 patch.object(liveness, "_check_stored_access_token", return_value={"id": "user-1"}), \
                 patch.object(liveness, "_account_totp_secret", return_value="JBSWY3DPEHPK3PXP"), \
                 patch.object(liveness, "_warm_authenticated_session") as warm, \
                 patch.object(liveness, "_login_via_reauth") as reauth:
                result = liveness.check_account_liveness("user@example.com", proxy="")

        self.assertTrue(result["ok"])
        self.assertEqual(result["access_token"], "old-token")
        warm.assert_not_called()
        reauth.assert_not_called()
        self.assertTrue(session.session.closed)

    def test_service_403_is_inconclusive_and_rotates_live_proxy_once(self):
        slot = _DummyQueueSlot()
        failed = {"ok": False, "status": "failed", "error": "HTTP Error 403: blocked"}
        with patch.object(live_service, "_QUEUE_SLOTS", slot), \
             patch.object(live_service.db, "mark_account_live_check_running", return_value=True), \
             patch.object(live_service.db, "get_account", return_value={"email_source": "remail"}), \
             patch.object(live_service.db, "update_account_liveness"), \
             patch.object(live_service, "_append_log"), \
             patch.object(live_service, "_pick_live_proxy", side_effect=["socks5://proxy-a.example:1080", "socks5://proxy-b.example:1080"]), \
             patch.object(live_service, "check_account_liveness", return_value=failed) as check:
            result = live_service._run_live_check(
                account_id=1,
                email="user@example.com",
                proxy=None,
                trigger="manual",
            )

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(check.call_args_list[0].kwargs["proxy"], "socks5://proxy-a.example:1080")
        self.assertEqual(check.call_args_list[1].kwargs["proxy"], "socks5://proxy-b.example:1080")
        self.assertEqual(check.call_args_list[0].kwargs["email_source"], "remail")
        self.assertEqual(check.call_count, 2)
        self.assertTrue(slot.released)

    def test_service_connection_closed_rotates_proxy_once(self):
        slot = _DummyQueueSlot()
        failed = {"ok": False, "status": "failed", "error": "Page.goto: net::ERR_CONNECTION_CLOSED"}
        recovered = {"ok": True, "status": "live", "access_token": "new-token"}
        with patch.object(live_service, "_QUEUE_SLOTS", slot), \
             patch.object(live_service.db, "mark_account_live_check_running", return_value=True), \
             patch.object(live_service.db, "get_account", return_value={}), \
             patch.object(live_service.db, "update_account_liveness"), \
             patch.object(live_service, "_append_log"), \
             patch.object(live_service, "_pick_live_proxy", side_effect=["socks5://proxy-a.example:1080", "socks5://proxy-b.example:1080"]), \
             patch.object(live_service, "_prepare_live_route", side_effect=lambda proxy: (live_service._live_route(proxy), None)), \
             patch.object(live_service, "check_account_liveness", side_effect=[failed, recovered]) as check:
            result = live_service._run_live_check(account_id=1, email="user@example.com", proxy=None, trigger="manual")
        self.assertTrue(result["ok"])
        self.assertEqual(check.call_count, 2)
        self.assertEqual(check.call_args_list[1].kwargs["proxy"], "socks5://proxy-b.example:1080")
        self.assertTrue(slot.released)


if __name__ == "__main__":
    unittest.main()
