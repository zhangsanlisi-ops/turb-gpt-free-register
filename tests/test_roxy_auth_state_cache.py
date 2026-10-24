"""Regression test: clearing a stale login must not flush CDN asset cache."""
import unittest
from unittest.mock import Mock, patch

from core import roxy_registration


class _FakeDriver:
    def __init__(self):
        self.commands = []
        self.navigations = []

    def execute_cdp_cmd(self, name, params):
        self.commands.append((name, params))

    def get(self, url):
        self.navigations.append(url)


class RoxyAuthStateCacheTests(unittest.TestCase):
    def test_stale_login_cleanup_keeps_http_cache(self):
        driver = _FakeDriver()
        with patch.object(roxy_registration, "_safe_get") as navigate:
            roxy_registration._clear_chatgpt_auth_state(driver, reason="test")
        names = [name for name, _ in driver.commands]
        self.assertIn("Network.clearBrowserCookies", names)
        self.assertEqual(names.count("Storage.clearDataForOrigin"), 3)
        self.assertNotIn("Network.clearBrowserCache", names)
        navigate.assert_called_once()


    def test_visible_login_entry_precedes_stale_shell_cleanup(self):
        driver = Mock()
        marker = object()
        state = {"url": "https://chatgpt.com/", "actions": [{"attrs": "accounts-profile-button"}]}
        with patch.object(roxy_registration, "_is_chrome_error_page", return_value=False), \
             patch.object(roxy_registration, "_find_visible_email_input_js", side_effect=[None, marker]), \
             patch.object(roxy_registration, "_email_entry_state", return_value=state), \
             patch.object(roxy_registration, "_dismiss_welcome_overlay", return_value=False), \
             patch.object(roxy_registration, "_is_wait_moment_state", return_value=False), \
             patch.object(roxy_registration, "_click_login_entry_option", return_value=True) as login, \
             patch.object(roxy_registration, "_looks_like_logged_in_chat_app", return_value=True) as stale, \
             patch.object(roxy_registration, "_clear_chatgpt_auth_state") as clear, \
             patch.object(roxy_registration, "_assert_not_external_idp"), \
             patch.object(roxy_registration.time, "sleep"):
            result = roxy_registration._wait_for_email_input(driver, timeout=2)
        self.assertIs(result, marker)
        login.assert_called_once()
        stale.assert_not_called()
        clear.assert_not_called()


if __name__ == "__main__":
    unittest.main()
