"""Offline tests for scripts/claude-account sync/use: picking up new logins never loses one.
Uses throw-away folders and fake logins.

Run: python3 -m unittest -v test_claude_account
"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "scripts" / "claude-account"


class ClaudeAccountTests(unittest.TestCase):
    def setUp(self):
        root = Path(tempfile.mkdtemp())
        self.acc, self.live, self.cfg = root / "accounts", root / "credentials.json", root / "claude.json"
        self.cfg.write_text(json.dumps({"other": 1}))

    def cli(self, *args):
        env = dict(os.environ, CLAUDE_ACCOUNTS_DIR=str(self.acc), CLAUDE_CREDENTIALS=str(self.live),
                   CLAUDE_JSON=str(self.cfg))
        return subprocess.run([str(SCRIPT), *args], capture_output=True, text=True, env=env)

    def login_as(self, uuid, email, token):
        self.live.write_text(json.dumps({"claudeAiOauth": {"accessToken": token, "subscriptionType": "max"}}))
        cfg = json.loads(self.cfg.read_text())
        cfg["oauthAccount"] = {"accountUuid": uuid, "emailAddress": email}
        self.cfg.write_text(json.dumps(cfg))

    def saved_token(self, name):
        return json.loads((self.acc / name / "credentials.json").read_text())["claudeAiOauth"]["accessToken"]

    def test_sync_waits_for_the_login_to_settle_then_saves_it(self):
        self.login_as("u-1", "first@example.com", "t1")
        self.assertIn("settle", self.cli("sync").stdout)
        self.assertFalse((self.acc / "first").exists())
        self.assertIn("Added 'first'", self.cli("sync").stdout)
        self.assertEqual(self.saved_token("first"), "t1")
        self.assertEqual(self.cli("status").stdout.split()[1], "first")

    def test_new_login_over_a_known_one_keeps_both(self):
        self.login_as("u-1", "first@example.com", "t1")
        self.cli("sync"), self.cli("sync")
        self.login_as("u-1", "first@example.com", "t1b")  # Claude Code renewed the token
        self.cli("sync"), self.cli("sync")
        self.assertEqual(self.saved_token("first"), "t1b")
        self.login_as("u-2", "first@example.net", "t2")  # /login with another account, same local part
        self.cli("sync")
        self.assertIn("Added 'first-2'", self.cli("sync").stdout)
        self.assertEqual(self.saved_token("first"), "t1b")
        self.assertEqual(self.saved_token("first-2"), "t2")
        self.assertEqual(self.cli("use", "first").returncode, 0)
        self.assertEqual(json.loads(self.live.read_text())["claudeAiOauth"]["accessToken"], "t1b")
        self.assertEqual(json.loads(self.cfg.read_text())["other"], 1)

    def test_use_refuses_to_drop_an_unsaved_login(self):
        self.login_as("u-1", "first@example.com", "t1")
        self.cli("sync"), self.cli("sync")
        self.login_as("u-9", "new@example.com", "t9")
        r = self.cli("use", "first")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(json.loads(self.live.read_text())["claudeAiOauth"]["accessToken"], "t9")
        self.assertEqual(self.saved_token("first"), "t1")


if __name__ == "__main__":
    unittest.main()
