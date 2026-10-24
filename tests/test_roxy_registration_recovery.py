# -*- coding: utf-8 -*-
"""Regression coverage for the two most recent Roxy registration failures."""
import unittest
from unittest.mock import Mock, patch

import requests

from core import roxy_registration as registration
from core.roxybrowser_client import RoxyBrowserClient


class _Response:
    status_code = 200
    text = '{"code": 0}'

    @staticmethod
    def json():
        return {"code": 0}


class RoxyRecoveryTests(unittest.TestCase):
    def test_create_retries_after_connection_refused(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000")
        client.http = Mock()
        client.http.request.side_effect = [
            requests.exceptions.ConnectionError("connection refused"),
            _Response(),
        ]

        with patch("core.roxybrowser_client.time.sleep"), patch(
            "core.roxybrowser_client._cfg.ROXY_API_RETRIES", 2
        ):
            payload = client.request("POST", "/browser/create", json_body={"workspaceId": "1"})

        self.assertEqual(payload, {"code": 0})
        self.assertEqual(client.http.request.call_count, 2)

    def test_create_timeout_checks_for_existing_profile_then_retries_once(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000")
        client.request = Mock(side_effect=[
            RuntimeError("Roxy API 返回失败 POST /browser/create: timeout of 15000ms exceeded"),
            {"data": {"dirId": "created-after-retry"}},
        ])
        client._find_profile_by_window_name = Mock(return_value="")

        with patch("core.roxybrowser_client.time.sleep"), patch(
            "core.roxybrowser_client._random_roxy_profile_name", return_value="rb-timeout-test"
        ), patch("core.roxybrowser_client._cfg.ROXY_RANDOM_PROFILE_NAME_ON_CREATE", True), patch(
            "core.roxybrowser_client._cfg.ROXY_WORKSPACE_ID", "workspace-1"
        ), patch("core.roxybrowser_client._cfg.ROXY_PROJECT_ID", ""):
            profile_id = client.create_profile()

        self.assertEqual(profile_id, "created-after-retry")
        self.assertEqual(client.request.call_count, 2)
        client._find_profile_by_window_name.assert_called_once_with("workspace-1", "rb-timeout-test")

    def test_email_stall_uses_nextauth_fallback_once(self):
        driver = Mock()
        driver.current_url = "https://chatgpt.com/?slm=1"
        with patch.object(registration, "_type_email_address"), patch.object(
            registration,
            "_email_input_value_state",
            return_value={"inputs": [{"value": "new@example.com"}]},
        ), patch.object(registration, "_submit_email_step"), patch.object(
            registration,
            "_wait_email_submit_next_state",
            side_effect=["email_page", "password"],
        ), patch.object(
            registration,
            "_submit_email_via_browser_nextauth",
            return_value={"ok": True, "stage": "redirect"},
        ) as nextauth, patch.object(registration, "human_delay"):
            state = registration._submit_email_and_wait_next(driver, "new@example.com", attempts=1)

        self.assertEqual(state, "password")
        nextauth.assert_called_once_with(driver, "new@example.com")

    def test_homepage_without_email_input_returns_ui_stalled_early(self):
        clock = [0.0]

        def now():
            return clock[0]

        def sleep(seconds):
            clock[0] += seconds

        with patch.object(registration, "_has_access_token", return_value=False), patch.object(
            registration, "_is_login_password_page", return_value=False
        ), patch.object(registration, "_is_email_verification_page", return_value=False), patch.object(
            registration, "_is_signup_password_page", return_value=False
        ), patch.object(
            registration,
            "_email_input_value_state",
            return_value={"inputs": [], "url": "https://chatgpt.com/?slm=1"},
        ), patch.object(registration.time, "time", side_effect=now), patch.object(
            registration.time, "sleep", side_effect=sleep
        ), patch.object(registration._cfg, "ROXY_EMAIL_UI_STALL_SECONDS", 2):
            result = registration._wait_email_submit_next_state(object(), "new@example.com", timeout=12)

        self.assertEqual(result, "ui_stalled")
        self.assertLess(clock[0], 12)

    def test_otp_page_does_not_switch_to_password_by_default(self):
        with patch.object(registration, "_is_email_verification_page", return_value=True), patch.object(
            registration, "_click_continue_with_password_if_present"
        ) as continue_with_password, patch.object(
            registration._cfg, "ROXY_PREFER_PASSWORD_SIGNUP", False
        ):
            result = registration._fill_password_page_if_present(object(), "new@example.com", timeout=1)

        self.assertIsNone(result)
        continue_with_password.assert_not_called()


if __name__ == "__main__":
    unittest.main()
