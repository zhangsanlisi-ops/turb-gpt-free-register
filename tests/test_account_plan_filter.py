# -*- coding: utf-8 -*-
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import db, chatgpt_plan


class AccountPlanFilterTests(unittest.TestCase):
    def test_roxy_plan_check_retries_transient_connection_failure(self):
        route = {"network_route": "roxy_browser", "proxy": "http://127.0.0.1:18100", "proxy_mode": "roxy_profile"}
        response = {"accounts": {"default": {"account": {"plan_type": "free"}}}}
        with patch.object(chatgpt_plan, "resolve_plan_check_route", return_value=route), \
             patch.object(chatgpt_plan, "_maybe_start_plan_proxy_chain", return_value=(route, None)), \
             patch.object(chatgpt_plan, "_check_account_plan_via_roxy_browser", side_effect=[
                 (None, {"error": "net::ERR_CONNECTION_CLOSED"}),
                 (response, {"http_status": 200}),
             ]) as browser, \
             patch.object(chatgpt_plan.time, "sleep"):
            result = chatgpt_plan.check_account_plan("sample-token", max_attempts=2, retry_delay=0)
        self.assertTrue(result["ok"])
        self.assertEqual(result["attempt_count"], 2)
        self.assertEqual(browser.call_count, 2)

    def test_backfill_corrects_existing_three_month_half_price_trial(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            accounts_path = root / "accounts.json"
            accounts_path.write_text(json.dumps([
                {
                    "id": 557, "current_plan_type": "free", "plus_trial_eligible": True,
                    "plus_trial_campaign_id": "plus-3-months-50-pct-off",
                    "plus_trial_discount_percentage": 50,
                    "plus_trial_duration_num_periods": 3,
                    "plus_trial_duration_period": "month",
                },
                {
                    "id": 558, "current_plan_type": "free", "plus_trial_eligible": True,
                    "plus_trial_campaign_id": "plus-2-months-50-pct-off",
                    "plus_trial_discount_percentage": 50,
                    "plus_trial_duration_num_periods": 2,
                    "plus_trial_duration_period": "month",
                },
            ]), encoding="utf-8")
            missing = root / "missing.json"
            with patch.multiple(
                db,
                _ACCOUNTS_JSON=accounts_path,
                _LEGACY_ACCOUNTS_JSON=missing,
                _OUTLOOK_JSON=missing,
                _GENERIC_API_EMAIL_JSON=missing,
                _JOBS_JSON=missing,
                _DOMAIN_EMAIL_JSON=missing,
            ), patch.object(db, "_SQLITE_READY", False), patch.object(db, "_SQLITE_READY_PATH", None):
                self.assertEqual(db.backfill_half_price_promos(), 2)
                self.assertEqual(db.backfill_half_price_promos(), 0)
                account = db.get_account(557)
                self.assertEqual(account["promo_status"], "NON_ZERO_PROMO")
                self.assertEqual(account["plus_half_price_months"], 3)
                self.assertFalse(account["plus_trial_eligible"])
                self.assertEqual([r["id"] for r in db.list_accounts_page(limit=10, plan_filter="half_price_3m")["items"]], [557])
                snapshot = db.list_account_plan_check_statuses(limit=10, plan_filter="half_price_3m")
                self.assertEqual(snapshot["items"][0]["promo_status"], "NON_ZERO_PROMO")
                self.assertEqual(snapshot["items"][0]["plus_half_price_months"], 3)
                two_month_account = db.get_account(558)
                self.assertEqual(two_month_account["promo_status"], "NON_ZERO_PROMO")
                self.assertEqual(two_month_account["plus_half_price_months"], 2)
                self.assertFalse(two_month_account["plus_trial_eligible"])
                self.assertEqual([r["id"] for r in db.list_accounts_page(limit=10, plan_filter="half_price_2m")["items"]], [558])
                self.assertEqual([r["id"] for r in db.list_account_plan_check_statuses(limit=10, plan_filter="half_price_2m")["items"]], [558])

    def test_half_price_campaigns_are_non_zero_promos_not_trials(self):
        for months in (1, 2, 3):
            with self.subTest(months=months):
                data = {"accounts": {"default": {
                    "account": {"plan_type": "free"},
                    "eligible_promo_campaigns": {"plus": {
                        "id": f"plus-{months}-month{'s' if months != 1 else ''}-50-pct-off",
                        "metadata": {"discount": {"percentage": 50}, "duration": {"num_periods": months, "period": "month"}},
                    }},
                }}}
                result = chatgpt_plan.parse_accounts_check(data)
                self.assertEqual(result["promo_status"], "NON_ZERO_PROMO")
                self.assertEqual(result["plus_half_price_months"], months)
                self.assertEqual(result["plus_half_price_discount_percentage"], 50)
                self.assertFalse(result["plus_trial_eligible"])

        alternate = {"accounts": {"default": {
            "account": {"plan_type": "free"},
            "eligible_promo_campaigns": {"plus": {
                "id": "plus-monthly-half-off",
                "metadata": {"discount": {"percentage": 50}, "duration": {"num_periods": 1, "period": "month"}},
            }},
        }}}
        self.assertEqual(chatgpt_plan.parse_accounts_check(alternate)["plus_half_price_months"], 1)
        alternate["accounts"]["default"]["eligible_promo_campaigns"]["plus"]["metadata"]["duration"]["num_periods"] = 2
        self.assertEqual(chatgpt_plan.parse_accounts_check(alternate)["plus_half_price_months"], 2)

    def test_half_price_filters_separate_promos_from_free_and_trial(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            accounts_path = root / "accounts.json"
            accounts_path.write_text(json.dumps([
                {"id": 1, "current_plan_type": "free", "promo_status": "NON_ZERO_PROMO", "plus_half_price_months": 3},
                {"id": 2, "current_plan_type": "free", "promo_status": "NON_ZERO_PROMO", "plus_half_price_months": 1},
                {"id": 3, "current_plan_type": "free", "plus_trial_eligible": True},
                {"id": 4, "current_plan_type": "free"},
                {"id": 5, "current_plan_type": "free", "promo_status": "NON_ZERO_PROMO", "plus_half_price_months": 2},
            ]), encoding="utf-8")
            missing = root / "missing.json"
            with patch.multiple(
                db,
                _ACCOUNTS_JSON=accounts_path,
                _LEGACY_ACCOUNTS_JSON=missing,
                _OUTLOOK_JSON=missing,
                _GENERIC_API_EMAIL_JSON=missing,
                _JOBS_JSON=missing,
                _DOMAIN_EMAIL_JSON=missing,
            ), patch.object(db, "_SQLITE_READY", False), patch.object(db, "_SQLITE_READY_PATH", None):
                for name, expected in (("half_price_3m", [1]), ("half_price_2m", [5]), ("half_price_1m", [2]), ("free_plain", [4])):
                    result = db.list_accounts_page(limit=20, plan_filter=name)
                    self.assertEqual([item["id"] for item in result["items"]], expected)

                self.assertTrue(db.update_account_plan_check(4, result={
                    "ok": True, "current_plan_type": "free", "plus_trial_eligible": False,
                    "promo_status": "NON_ZERO_PROMO", "plus_half_price_eligible": True,
                    "plus_half_price_months": 3,
                    "plus_half_price_campaign_id": "plus-3-months-50-pct-off",
                    "plus_half_price_discount_percentage": 50,
                }))
                updated = db.get_account(4)
                self.assertEqual(updated["promo_status"], "NON_ZERO_PROMO")
                self.assertEqual(updated["plus_half_price_months"], 3)
                self.assertFalse(updated["plus_trial_eligible"])
                self.assertEqual({item["id"] for item in db.list_accounts_page(limit=20, plan_filter="half_price_3m")["items"]}, {1, 4})

    def test_plus_trial_filter_uses_sql_and_only_returns_eligible_free_accounts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            accounts_path = root / "accounts.json"
            accounts_path.write_text(json.dumps([
                {"id": 1, "email": "eligible@example.com", "current_plan_type": "free", "plus_trial_eligible": True},
                {"id": 2, "email": "not-eligible@example.com", "current_plan_type": "free", "plus_trial_eligible": False},
                {"id": 3, "email": "paid@example.com", "current_plan_type": "plus", "plus_trial_eligible": True},
                {"id": 4, "email": "missing-plan@example.com", "plus_trial_eligible": True},
            ], ensure_ascii=False), encoding="utf-8")

            missing = root / "missing.json"
            with patch.multiple(
                db,
                _ACCOUNTS_JSON=accounts_path,
                _LEGACY_ACCOUNTS_JSON=missing,
                _OUTLOOK_JSON=missing,
                _GENERIC_API_EMAIL_JSON=missing,
                _JOBS_JSON=missing,
                _DOMAIN_EMAIL_JSON=missing,
            ), patch.object(db, "_SQLITE_READY", False), patch.object(db, "_SQLITE_READY_PATH", None):
                for filter_name in ("plus_trial", "plus_trial_eligible", "trial"):
                    result = db.list_accounts_page(limit=20, plan_filter=filter_name)
                    self.assertEqual([item["id"] for item in result["items"]], [1])

                snapshot = db.list_account_plan_check_statuses(limit=20, plan_filter="plus_trial")
                self.assertEqual([item["id"] for item in snapshot["items"]], [1])


    def test_plan_check_preserves_existing_trial_when_latest_response_has_no_promo(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            accounts_path = root / "accounts.json"
            accounts_path.write_text(json.dumps([
                {
                    "id": 1,
                    "email": "eligible@example.com",
                    "current_plan_type": "free",
                    "plus_trial_eligible": True,
                    "plus_trial_campaign_id": "plus-1-month-free",
                    "plus_trial_title": "Try Plus free for 1 month",
                },
            ], ensure_ascii=False), encoding="utf-8")

            missing = root / "missing.json"
            with patch.multiple(
                db,
                _ACCOUNTS_JSON=accounts_path,
                _LEGACY_ACCOUNTS_JSON=missing,
                _OUTLOOK_JSON=missing,
                _GENERIC_API_EMAIL_JSON=missing,
                _JOBS_JSON=missing,
                _DOMAIN_EMAIL_JSON=missing,
            ), patch.object(db, "_SQLITE_READY", False), patch.object(db, "_SQLITE_READY_PATH", None):
                ok = db.update_account_plan_check(1, result={
                    "ok": True,
                    "checked_at": "2026-09-17T00:00:00",
                    "http_status": 200,
                    "current_plan_type": "free",
                    "plus_trial_eligible": False,
                    "eligible_offer_ids": [],
                })
                self.assertTrue(ok)
                updated = db.get_account(1)
                self.assertTrue(updated["plus_trial_eligible"])
                self.assertEqual(updated["plus_trial_campaign_id"], "plus-1-month-free")
                self.assertTrue(updated["plan_check_trial_preserved"])



    def test_imrun_proxy_marker_uses_roxy_route_not_curl_or_imrun(self):
        route = chatgpt_plan.resolve_plan_check_route("imrun:default")
        self.assertEqual(route["network_route"], "roxy_browser")
        self.assertEqual(route["proxy_mode"], "roxy_profile")
        self.assertEqual(route["proxy"], "")
        self.assertIn("RoxyBrowser", route["proxy_used"])

    def test_host_port_user_pass_proxy_is_normalized_and_uses_roxy_browser(self):
        route = chatgpt_plan.resolve_plan_check_route("us.1024proxy.io:3000:user:pass")
        self.assertEqual(route["network_route"], "roxy_browser")
        self.assertEqual(route["proxy_mode"], "roxy_profile")
        self.assertTrue(route["proxy"].startswith("http://user:pass@us.1024proxy.io:3000"))
        self.assertEqual(route["proxy_used"], "http://***:***@us.1024proxy.io:3000")



if __name__ == "__main__":
    unittest.main()
