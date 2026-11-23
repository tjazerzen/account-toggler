"""Tests for scripts/check_secrets.py in a throwaway git repo (fake secrets only).

Run: python3 -m unittest -v test_check_secrets
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "scripts" / "check_secrets.py"
FAKE_SECRET = "fake" + "-value-" + "8d1f2a9c4e"        # built at runtime so scanners ignore this file
PRIVATE = "my-private-" + "hostname-q7"
OUTSIDER = "dev" + "@" + "corp.invalid"


class LeakCheckTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.git("init", "-q")
        self.git("config", "user.email", "1+bot@users.noreply.github.com")
        self.git("config", "user.name", "bot")
        (self.repo / "scripts").mkdir()
        shutil.copy(SCRIPT, self.repo / "scripts" / "check_secrets.py")
        (self.repo / ".env").write_text("MASTER_" + "PASSWORD=" + FAKE_SECRET + "\n")
        (self.repo / ".leakcheck-denylist").write_text(PRIVATE + "\n")
        (self.repo / ".gitignore").write_text(".env\n.leakcheck-denylist\n")
        self.commit("README.md", "hello\n")

    def tearDown(self):
        shutil.rmtree(self.repo)

    def git(self, *args, env=None):
        return subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True,
                              env={**os.environ, **(env or {})}).stdout.decode()

    def commit(self, name, content, msg="update", env=None):
        path = self.repo / name
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        self.git("add", "-f", name)
        self.git("commit", "-q", "--no-verify", "-m", msg, env=env)

    def check(self, *args, env=None):
        r = subprocess.run(["python3", "-I", "scripts/check_secrets.py", *args], cwd=self.repo,
                           capture_output=True, text=True, env={**os.environ, **(env or {})})
        self.assertNotIn(FAKE_SECRET, r.stdout + r.stderr)  # findings never echo the secret
        return r.returncode, r.stderr

    def stage(self, name, content):
        path = self.repo / name
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        self.git("add", "-f", name)

    def test_clean_repo_passes(self):
        self.assertEqual(self.check("--all")[0], 0)
        self.assertEqual(self.check("--history", "HEAD")[0], 0)

    def test_env_file_refused(self):
        self.git("add", "-f", ".env")
        code, err = self.check("--staged")
        self.assertEqual(code, 1)
        self.assertIn(".env: this file must never be committed", err)

    def test_secret_value_found_even_with_allow_marker(self):
        self.stage("notes.txt", f"x = '{FAKE_SECRET}'  # leakcheck:allow\n")
        self.assertEqual(self.check("--staged")[0], 1)

    def test_secret_in_utf16_file(self):
        self.stage("notes.txt", f"token {FAKE_SECRET}".encode("utf-16"))
        self.assertEqual(self.check("--staged")[0], 1)

    def test_denylist_case_insensitive(self):
        self.stage("notes.md", f"see {PRIVATE.upper()}\n")
        self.assertEqual(self.check("--staged")[0], 1)

    def test_denylist_from_ci_secret(self):
        (self.repo / ".leakcheck-denylist").unlink()
        self.stage("notes.md", "served at secret-domain.example\n")
        self.assertEqual(self.check("--staged")[0], 0)
        self.assertEqual(self.check("--staged", env={"LEAKCHECK_DENYLIST": "secret-domain.example"})[0], 1)

    def test_history_catches_deleted_secret(self):
        self.commit("oops.txt", f"{FAKE_SECRET}\n", msg="oops")   # committed with --no-verify
        self.git("rm", "-q", "oops.txt")
        self.git("commit", "-q", "--no-verify", "-m", "remove")
        self.assertEqual(self.check("--all")[0], 0)                # working tree is clean...
        code, err = self.check("--history", "HEAD")                # ...but history is not
        self.assertEqual(code, 1)
        self.assertIn("history", err)

    def test_history_catches_personal_emails(self):
        self.commit("a.txt", "a\n", msg=f"fix\n\nCo-authored-by: X <{OUTSIDER}>")
        self.assertEqual(self.check("--history", "HEAD")[0], 1)

    def test_history_catches_author_identity(self):
        self.commit("b.txt", "b\n", env={"GIT_AUTHOR_EMAIL": OUTSIDER})
        code, err = self.check("--history", "HEAD")
        self.assertEqual(code, 1)
        self.assertIn("author/committer email", err)
        self.assertNotIn(OUTSIDER, err)  # masked

    def test_message_lines_that_look_like_diff_lines(self):
        self.commit("c.txt", "c\n", msg=f"fix\n\n- thanks to {OUTSIDER}\n    reported by {OUTSIDER}")
        self.assertEqual(self.check("--history", "HEAD")[0], 1)

    def test_annotated_tag_message(self):
        self.git("tag", "-a", "v1", "-m", f"release, ping {OUTSIDER}")
        self.assertEqual(self.check("--history", "HEAD")[0], 1)

    def test_scanner_config_files_refused(self):
        self.stage(".gitleaks.toml", "[allowlist]\npaths = ['.*']\n")
        code, err = self.check("--staged")
        self.assertEqual(code, 1)
        self.assertIn(".gitleaks.toml: this file must never be committed", err)

    def test_worktree_uses_main_checkout_secrets(self):
        wt = self.repo.parent / (self.repo.name + "-wt")
        self.git("worktree", "add", "-q", str(wt))
        try:
            (wt / "leak.txt").write_text(FAKE_SECRET + "\n")
            subprocess.run(["git", "add", "leak.txt"], cwd=wt, check=True)
            # the hooks run an installed copy from the shared .git dir, with cwd = the worktree
            r = subprocess.run(["python3", "-I", str(self.repo / "scripts" / "check_secrets.py"),
                                "--staged", "--require-local"],
                               cwd=wt, capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("secret value from your local .env", r.stderr)
        finally:
            self.git("worktree", "remove", "--force", str(wt))

    def test_require_local_fails_closed(self):
        (self.repo / ".env").unlink()
        (self.repo / ".leakcheck-denylist").unlink()
        self.assertEqual(self.check("--staged")[0], 0)
        code, err = self.check("--staged", "--require-local")
        self.assertEqual(code, 1)
        self.assertIn("no .env or .leakcheck-denylist", err)

    def test_token_patterns(self):
        self.stage("cfg.sh", "export GH_" + "TOKEN=ghp_" + "a" * 36 + "\n")
        self.assertEqual(self.check("--staged")[0], 1)


if __name__ == "__main__":
    unittest.main()
