# -*- coding: utf-8 -*-
"""Secret-copy lookups must not deserialize the whole accounts table per ID."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import db


class AccountSecretLookupTests(unittest.TestCase):
    def test_targeted_single_and_bulk_lookup(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            accounts_path = root / "accounts.json"
            accounts_path.write_text(json.dumps([
                {"id": 1, "email": "one@example.com", "access_token": "token-one"},
                {"id": 2, "email": "two@example.com", "access_token": "token-two"},
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
                db._ensure_sqlite()
                with patch.object(db, "_load_accounts", side_effect=AssertionError("full table scan")):
                    self.assertEqual(db.get_account(2)["access_token"], "token-two")
                    self.assertIsNone(db.get_account(999))
                    found = db.get_accounts_by_ids([2, 1, 2, *range(3, 405)])
                self.assertEqual(set(found), {1, 2})
                self.assertEqual(found[1]["access_token"], "token-one")
                self.assertEqual(found[2]["access_token"], "token-two")


if __name__ == "__main__":
    unittest.main()
