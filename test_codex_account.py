"""Offline tests for scripts/codex-account: switching never loses a login.
Uses throw-away CODEX_HOME / CODEX_ACCOUNTS_DIR folders with fake logins.

Run: python3 -m unittest -v test_codex_account
"""
import base64
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "scripts" / "codex-account"


def jwt(claims):
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"h.{body}.s"


def login(acct, email, refresh="r1"):
    return json.dumps({"auth_mode": "chatgpt", "tokens": {
        "account_id": acct, "access_token": jwt({"exp": 1}), "refresh_token": refresh,
        "id_token": jwt({"email": email, "https://api.openai.com/auth": {"chatgpt_plan_type": "plus"}})}})


class CodexAccountTests(unittest.TestCase):
    def setUp(self):
        root = Path(tempfile.mkdtemp())
        self.home, self.acc = root / "codex", root / "accounts"
        self.home.mkdir()

    def cli(self, *args):
        env = dict(os.environ, CODEX_HOME=str(self.home), CODEX_ACCOUNTS_DIR=str(self.acc))
        return subprocess.run([str(SCRIPT), *args], capture_output=True, text=True, env=env)

    def live(self):
        return json.loads((self.home / "auth.json").read_text())["tokens"]

    def saved(self, name):
        return json.loads((self.acc / name / "auth.json").read_text())["tokens"]

    def setup_two(self):
        (self.home / "auth.json").write_text(login("acct-a", "a@example.com"))
        self.assertEqual(self.cli("save", "main").returncode, 0)
        (self.acc / "other").mkdir()
        (self.acc / "other" / "auth.json").write_text(login("acct-b", "b@example.com"))

    def test_list_marks_the_live_login(self):
        self.setup_two()
        rows = json.loads(self.cli("list", "--json").stdout)
        self.assertEqual([(r["name"], r["email"], r["plan"], r["active"]) for r in rows],
                         [("main", "a@example.com", "plus", True), ("other", "b@example.com", "plus", False)])
        self.assertNotIn("r1", self.cli("list").stdout + self.cli("list", "--json").stdout)

    def test_switch_keeps_tokens_codex_renewed_meanwhile(self):
        self.setup_two()
        (self.home / "auth.json").write_text(login("acct-a", "a@example.com", refresh="r2"))  # Codex renewed
        self.assertEqual(self.cli("use", "other").returncode, 0)
        self.assertEqual(self.live()["account_id"], "acct-b")
        self.assertEqual(self.saved("main")["refresh_token"], "r2")
        self.assertEqual(oct((self.home / "auth.json").stat().st_mode & 0o777), "0o600")
        self.assertEqual(self.cli("toggle").returncode, 0)
        self.assertEqual(self.live()["account_id"], "acct-a")

    def test_refuses_to_drop_an_unsaved_login(self):
        self.setup_two()
        (self.home / "auth.json").write_text(login("acct-z", "z@example.com"))
        r = self.cli("use", "other")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("isn't saved", r.stderr)
        self.assertEqual(self.live()["account_id"], "acct-z")

    def test_save_refuses_a_login_saved_under_another_name(self):
        self.setup_two()
        r = self.cli("save", "again")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.acc / "again").exists())

    def test_unknown_account(self):
        self.setup_two()
        self.assertNotEqual(self.cli("use", "nope").returncode, 0)
        self.assertEqual(self.live()["account_id"], "acct-a")


if __name__ == "__main__":
    unittest.main()
