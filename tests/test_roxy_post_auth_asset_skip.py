"""Post-auth CDN skipping must preserve and restore the existing saver rules."""
import unittest
from unittest.mock import Mock

from core.roxy_registration import _enable_post_auth_asset_skip, _restore_post_auth_asset_skip


class PostAuthAssetSkipTests(unittest.TestCase):
    def test_enable_and_restore_preserve_original_rules(self):
        driver = Mock()
        saver = Mock()
        saver._selenium_patterns = ["*existing-rule*"]
        original = _enable_post_auth_asset_skip(driver, saver)
        self.assertEqual(original, ["*existing-rule*"])
        enabled = driver.execute_cdp_cmd.call_args_list[0].args[1]["urls"]
        self.assertIn("*existing-rule*", enabled)
        self.assertTrue(any("chatgpt.com/cdn/assets/" in x and ".js" in x for x in enabled))
        self.assertTrue(any("chatgpt.com/cdn/assets/" in x and ".css" in x for x in enabled))
        self.assertEqual(saver._selenium_patterns, enabled)
        _restore_post_auth_asset_skip(driver, saver, original)
        self.assertEqual(driver.execute_cdp_cmd.call_args_list[-1].args[1]["urls"], original)
        self.assertEqual(saver._selenium_patterns, original)

    def test_enable_failure_keeps_original_rules(self):
        driver = Mock()
        driver.execute_cdp_cmd.side_effect = RuntimeError("CDP unavailable")
        saver = Mock()
        saver._selenium_patterns = ["*existing-rule*"]
        self.assertIsNone(_enable_post_auth_asset_skip(driver, saver))
        self.assertEqual(saver._selenium_patterns, ["*existing-rule*"])


if __name__ == "__main__":
    unittest.main()
