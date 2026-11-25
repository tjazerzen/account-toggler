"""Offline tests: auto-switch rules, login/session security, and the HTTP surface.
Nothing here touches real credentials, the real .env, or the network.

Run: python3 -m unittest -v test_server
"""
import base64
import http.client
import io
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

_tmp = Path(tempfile.mkdtemp())
PASSWORD = "unit-test-pass-phrase"  # leakcheck:allow (test fixture, not a real secret)
os.environ.update({
    "ENV_FILE": str(_tmp / "no.env"),  # never load the real .env
    "STATE_FILE": str(_tmp / "state.json"),
    "PRIORITY": "main,backup",
    "THRESHOLD": "90",
    "MASTER_PASSWORD": PASSWORD,
    "SESSION_SECRET": "0" * 64,
    "ALLOWED_HOSTS": "claude.example.com",
    "PUBLIC_PORT": "1",  # the tests start their own listeners on random ports
})
import server  # noqa: E402

server.FAIL_DELAY = 0
DOMAIN = "claude.example.com"


def internet(ip, **extra):
    """Headers our reverse proxy adds for an HTTPS visitor."""
    return {"X-Forwarded-For": ip, "X-Forwarded-Proto": "https", **extra}


def iso(offset_s):
    return datetime.fromtimestamp(time.time() + offset_s, timezone.utc).isoformat()


class FakeVM:
    """Simulates claude-account + usage endpoint for two accounts with distinct tiers."""

    def __init__(self, active="main"):
        self.active = active
        self.usage = {"main": {}, "backup": {}}
        self.tiers = {"main": "default_claude_max_20x", "backup": "default_claude_max_5x"}
        self.live_tier = self.tiers[active]
        self.calls = []
        self.cc = None  # Claude Code's cached reading: (name, fetched_at, windows)
        self.codex_active = "main"
        self.codex_ids = {"main": "acct-1", "spare": "acct-2"}
        self.codex_expired = set()  # Codex accounts whose token has expired
        self.codex_usage = {n: {"windows": {"primary": {"u": 23.0, "resets_at": iso(86400), "label": "5-hour"}},
                                "plan": "plus", "email": f"{n}@example.com", "limit_reached": False}
                            for n in ("main", "spare")}
        self.codex_log = None  # Codex's latest session-log reading: (when, usage)

    def list_accounts(self):
        return {"error": None, "accounts": [
            {"name": n, "email": f"{n}@example.com", "plan": "max", "label": "Max", "active": n == self.active}
            for n in ("main", "backup")]}

    def run(self, *args, cli=None):
        if cli == server.CODEX_CLI:
            self.calls.append(("codex-use", args[1]))
            self.codex_active = args[1]
            return 0, f"Switched Codex to '{args[1]}'.", ""
        self.calls.append(args)
        if args[0] == "use":
            self.active = args[1]
            self.live_tier = self.tiers[args[1]]
        return 0, f"Switched to '{args[1]}'.", ""

    def read_oauth(self, path):
        path = Path(path)
        if path == server.LIVE:
            return "tok-" + self.active, self.live_tier
        name = path.parent.name
        return "tok-" + name, self.tiers[name]

    def fetch_usage(self, token):
        self.calls.append(("fetch", token))
        return self.usage[token.split("-", 1)[1]]

    def claude_code_reading(self, names):
        return self.cc

    def list_codex_accounts(self):
        return {"error": None, "accounts": [
            {"name": n, "email": f"{n}@example.com", "plan": "plus", "label": "Plus", "active": n == self.codex_active}
            for n in ("main", "spare")]}

    def read_codex_auth(self, path=None):
        path = Path(path)
        name = self.codex_active if path == server.CODEX_HOME / "auth.json" else path.parent.name
        return (None if name in self.codex_expired else "ctok-" + name), self.codex_ids[name]

    def fetch_codex_usage(self, token, account):
        name = token.split("-", 1)[1]
        assert self.codex_ids[name] == account
        self.calls.append(("codex", name))
        return json.loads(json.dumps(self.codex_usage[name]))

    def codex_session_reading(self):
        return self.codex_log


class FakeVMMixin:
    def setUp(self):
        self.vm = FakeVM()
        self.patches = [mock.patch.object(server, n, getattr(self.vm, n))
                        for n in ("list_accounts", "run", "read_oauth", "fetch_usage", "claude_code_reading",
                                  "list_codex_accounts", "read_codex_auth", "fetch_codex_usage",
                                  "codex_session_reading")]
        for p in self.patches:
            p.start()
        server.AUTO = self.auto = server.AutoSwitcher()
        self.auto.enabled, self.auto.usage, self.auto.events = True, {}, []
        self.auto.last_switch_at, self.auto.last_active = 0, None
        self.auto.codex_enabled, self.auto.codex_usage = True, {}
        self.auto.codex_last_switch_at, self.auto.codex_last_active, self.auto.codex_active_since = 0, None, 0

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def uses(self):
        return [c[1] for c in self.vm.calls if c[0] == "use"]


class AutoSwitchTests(FakeVMMixin, unittest.TestCase):
    def test_stays_on_main_below_threshold(self):
        self.vm.usage["main"] = {"five_hour": {"u": 89.0, "resets_at": iso(3600)}}
        self.auto.tick(force=True)
        self.assertEqual(self.uses(), [])

    def test_switches_at_threshold_and_back_after_reset(self):
        self.vm.usage["main"] = {"five_hour": {"u": 90.0, "resets_at": iso(3600)}}
        self.auto.tick(force=True)
        self.assertEqual(self.uses(), ["backup"])
        self.auto.tick(force=True)  # main still blocked: stay on backup
        self.assertEqual(self.uses(), ["backup"])
        self.vm.usage["main"] = {"five_hour": {"u": 3.0, "resets_at": iso(5 * 3600)}}
        self.auto.last_switch_at -= server.COOLDOWN + 1
        self.auto.tick(force=True)
        self.assertEqual(self.uses(), ["backup", "main"])

    def test_weekly_limit_also_triggers(self):
        self.vm.usage["main"] = {"seven_day": {"u": 95.0, "resets_at": iso(3 * 86400)}}
        self.auto.tick(force=True)
        self.assertEqual(self.uses(), ["backup"])

    def test_cached_reset_in_past_unblocks_without_fresh_data(self):
        self.auto.usage = {"main": {"windows": {"five_hour": {"u": 100.0, "resets_at": iso(-10)}}}}
        self.assertEqual(self.auto.blocking("main", time.time()), [])

    def test_both_blocked_stays_put(self):
        self.vm.usage["main"] = {"five_hour": {"u": 95.0, "resets_at": iso(3600)}}
        self.vm.usage["backup"] = {"five_hour": {"u": 99.0, "resets_at": iso(3600)}}
        self.auto.tick(force=True)
        self.assertEqual(self.uses(), [])

    def test_cooldown_blocks_rapid_switch(self):
        self.auto.last_switch_at = time.time()
        self.vm.usage["main"] = {"five_hour": {"u": 99.0, "resets_at": iso(3600)}}
        self.auto.tick(force=True)
        self.assertEqual(self.uses(), [])

    def test_disabled_never_switches(self):
        self.auto.enabled = False
        self.vm.usage["main"] = {"five_hour": {"u": 99.0, "resets_at": iso(3600)}}
        self.auto.tick(force=True)
        self.assertEqual(self.uses(), [])

    def test_identity_mismatch_pauses_instead_of_switching(self):
        self.vm.live_tier = self.vm.tiers["backup"]  # live login belongs to backup, current says main
        self.vm.usage["main"] = {"five_hour": {"u": 99.0, "resets_at": iso(3600)}}
        self.auto.tick(force=True)
        self.assertEqual(self.uses(), [])
        self.assertFalse(self.auto.enabled)
        self.assertEqual(self.auto.events[-1]["kind"], "error")

    def test_external_manual_switch_to_non_preferred_pauses_auto(self):
        self.auto.tick(force=True)
        self.vm.active = "backup"
        self.vm.live_tier = self.vm.tiers["backup"]
        self.auto.tick(force=True)
        self.assertFalse(self.auto.enabled)
        self.assertEqual(self.uses(), [])

    def test_usage_error_keeps_last_reading(self):
        self.vm.usage["main"] = {"five_hour": {"u": 50.0, "resets_at": iso(3600)}}
        self.auto.tick(force=True)
        with mock.patch.object(server, "fetch_usage", side_effect=RuntimeError("usage check failed (HTTP 429)")):
            self.auto.tick(force=True)
        self.assertEqual(self.auto.usage["main"]["windows"]["five_hour"]["u"], 50.0)
        self.assertIn("429", self.auto.usage["main"]["error"])

    def fetches(self):
        return [c[1] for c in self.vm.calls if c[0] == "fetch"]

    def test_rate_limited_check_backs_off(self):
        with mock.patch.object(server, "fetch_usage", side_effect=server.RateLimited("rate-limited")):
            self.auto.tick(force=True)
        u = self.auto.usage["main"]
        self.assertEqual(u["backoff"], 2 * server.POLL)
        self.assertIn("retrying in", u["error"])
        u["checked_at"] -= server.POLL  # a normal tick later: still inside the back-off, so no request
        self.auto.tick()
        self.assertNotIn("tok-main", self.fetches())
        u["retry_at"] = time.time() - 1
        self.auto.tick()
        self.assertIn("tok-main", self.fetches())
        self.assertIsNone(self.auto.usage["main"]["backoff"])

    def test_claude_code_reading_drives_switch_when_endpoint_is_rate_limited(self):
        self.vm.cc = ("main", time.time(), {"seven_day": {"u": 93.0, "resets_at": iso(86400)}})
        with mock.patch.object(server, "fetch_usage", side_effect=server.RateLimited("rate-limited")):
            self.auto.tick()
        self.assertEqual(self.uses(), ["backup"])
        self.assertIsNone(self.auto.usage["main"]["error"])

    def test_older_claude_code_reading_does_not_replace_newer_one(self):
        self.vm.usage["main"] = {"seven_day": {"u": 20.0, "resets_at": iso(86400)}}
        self.auto.tick(force=True)
        self.vm.cc = ("main", time.time() - 600, {"seven_day": {"u": 95.0, "resets_at": iso(86400)}})
        self.auto.tick(force=True)
        self.assertEqual(self.auto.usage["main"]["windows"]["seven_day"]["u"], 20.0)
        self.assertEqual(self.uses(), [])


class ClaudeCodeReadingTests(unittest.TestCase):
    def test_matches_profile_by_account_uuid(self):
        d = Path(tempfile.mkdtemp())
        for name, uuid in (("main", "uuid-a"), ("backup", "uuid-b")):
            (d / name).mkdir()
            (d / name / "oauthAccount.json").write_text(json.dumps({"accountUuid": uuid}))
        cfg = d / "claude.json"
        cfg.write_text(json.dumps({"cachedUsageUtilization": {
            "accountUuid": "uuid-b", "fetchedAtMs": 1_700_000_000_000,
            "utilization": {"five_hour": None, "seven_day": {"utilization": 41, "resets_at": "x"}}}}))
        with mock.patch.multiple(server, ACC_DIR=d, CLAUDE_CFG=cfg):
            self.assertEqual(server.claude_code_reading(["main", "backup"]),
                             ("backup", 1_700_000_000, {"seven_day": {"u": 41.0, "resets_at": "x"}}))
            cfg.write_text(json.dumps({"cachedUsageUtilization": {"accountUuid": "uuid-z", "fetchedAtMs": 1}}))
            self.assertIsNone(server.claude_code_reading(["main", "backup"]))
            cfg.write_text("not json")
            self.assertIsNone(server.claude_code_reading(["main", "backup"]))


class CodexTests(FakeVMMixin, unittest.TestCase):
    def codex_calls(self):
        return [c[1] for c in self.vm.calls if c[0] == "codex"]

    def codex_uses(self):
        return [c[1] for c in self.vm.calls if c[0] == "codex-use"]

    def view(self):
        return {a["name"]: a for a in self.auto.decorate(server.list_accounts())["codex"]["accounts"]}

    def test_asks_endpoint_for_every_account_with_its_own_token(self):
        self.auto.tick()
        self.assertEqual(sorted(self.codex_calls()), ["main", "spare"])
        v = self.view()
        self.assertTrue(v["main"]["active"])
        self.assertEqual([(w["label"], w["u"]) for w in v["spare"]["usage"]["windows"]], [("5-hour", 23.0)])
        self.assertEqual(v["main"]["usage"]["source"], "ChatGPT")

    def log(self, u, ago):
        self.vm.codex_log = (time.time() - ago, {"windows": {"primary": {
            "u": u, "resets_at": iso(3600), "label": "5-hour"}}, "plan": "plus"})

    def test_session_log_is_credited_to_the_active_account_only_after_it_went_live(self):
        self.auto.tick(force=True)
        self.vm.codex_active = "spare"
        self.log(41.0, 0)  # written right at the switch: could still be main's
        self.auto.tick(force=True)
        self.assertEqual(self.auto.codex_usage["main"]["windows"]["primary"]["u"], 23.0)
        self.assertEqual(self.auto.codex_usage["spare"]["source"], "ChatGPT")
        self.vm.codex_log = (time.time() + 30, self.vm.codex_log[1])  # a reply after the switch
        n = len(self.codex_calls())
        self.auto.tick()
        self.assertEqual(self.auto.codex_usage["spare"]["windows"]["primary"]["u"], 41.0)
        self.assertEqual(self.auto.codex_usage["spare"]["source"], "Codex's session log")
        self.assertEqual(self.auto.codex_usage["main"]["windows"]["primary"]["u"], 23.0)
        self.assertEqual(len(self.codex_calls()), n)

    def test_older_session_log_does_not_replace_newer_reading(self):
        self.auto.tick(force=True)
        self.log(80.0, 3600)
        self.auto.tick()
        self.assertEqual(self.auto.codex_usage["main"]["windows"]["primary"]["u"], 23.0)

    def test_expired_token_keeps_last_reading(self):
        self.auto.tick(force=True)
        self.vm.codex_expired = {"main", "spare"}
        self.auto.tick(force=True)
        self.assertEqual(len(self.codex_calls()), 2)
        self.assertEqual(self.auto.codex_usage["main"]["windows"]["primary"]["u"], 23.0)
        self.assertIn("Codex renews it", self.auto.codex_usage["main"]["error"])
        self.assertIn("saved login token expired", self.auto.codex_usage["spare"]["error"])

    def test_rate_limited_codex_check_backs_off(self):
        with mock.patch.object(server, "fetch_codex_usage", side_effect=server.RateLimited("rate-limited")):
            self.auto.tick(force=True)
        self.assertIn("retrying in", self.auto.codex_usage["main"]["error"])
        for c in self.auto.codex_usage.values():
            c["checked_at"] -= server.INACTIVE_POLL
        self.auto.tick()
        self.assertEqual(self.codex_calls(), [])

    def test_switches_codex_at_threshold_and_back_after_reset(self):
        self.vm.codex_usage["main"]["windows"]["primary"]["u"] = 92.0
        self.auto.tick()
        self.assertEqual(self.codex_uses(), ["spare"])
        self.assertEqual(self.uses(), [])  # Claude is untouched
        self.assertEqual(self.auto.events[-1]["kind"], "switch")
        self.vm.codex_usage["main"]["windows"]["primary"] = {"u": 1.0, "resets_at": iso(5 * 3600), "label": "5-hour"}
        self.auto.tick(force=True)  # cooldown still running
        self.assertEqual(self.codex_uses(), ["spare"])
        self.auto.codex_last_switch_at -= server.COOLDOWN + 1
        self.auto.tick(force=True)
        self.assertEqual(self.codex_uses(), ["spare", "main"])

    def test_never_switches_to_an_account_without_a_reading(self):
        self.vm.codex_active = "spare"  # spare is not preferred, main has no reading yet
        self.auto.codex_active_since = time.time() - 60
        self.vm.codex_log = (time.time() + 5, {"windows": {}, "plan": "plus"})  # empty: not fresh
        with mock.patch.object(server, "fetch_codex_usage", side_effect=RuntimeError("down")):
            self.auto.tick()
        self.assertEqual(self.codex_uses(), [])
        self.vm.codex_usage["main"]["windows"]["primary"]["u"] = 100.0
        self.auto.tick(force=True)  # the endpoint now says main is full: stay
        self.assertEqual(self.codex_uses(), [])
        self.assertTrue(self.auto.codex_enabled)

    def test_both_codex_accounts_full_stays_put(self):
        for n in ("main", "spare"):
            self.vm.codex_usage[n]["windows"]["primary"]["u"] = 99.0
        self.auto.tick()
        self.assertEqual(self.codex_uses(), [])

    def test_codex_auto_off_never_switches(self):
        self.auto.codex_enabled = False
        self.vm.codex_usage["main"]["windows"]["primary"]["u"] = 99.0
        self.auto.tick()
        self.assertEqual(self.codex_uses(), [])
        self.assertTrue(self.view()["main"]["blocked"])

    def test_outside_switch_to_non_preferred_pauses_codex_auto(self):
        self.auto.tick()
        self.vm.codex_active = "spare"
        self.auto.tick()
        self.assertFalse(self.auto.codex_enabled)
        self.assertTrue(self.auto.enabled)  # Claude's auto-switch is separate
        self.assertEqual(self.codex_uses(), [])

    def test_codex_limits_never_switch_claude(self):
        self.vm.codex_usage["main"]["windows"]["primary"]["u"] = 100.0
        self.vm.codex_usage["spare"]["windows"]["primary"]["u"] = 100.0
        self.auto.tick()
        self.assertEqual(self.uses(), [])

    def test_unsaved_live_login_is_reported(self):
        self.vm.codex_active = None
        st = self.auto.decorate(server.list_accounts())["codex"]
        self.assertIn("codex-account save", st["error"])


class CodexReadingTests(unittest.TestCase):
    def test_parses_usage_endpoint(self):
        got = server.parse_codex_usage({"plan_type": "plus", "email": "you@example.com", "rate_limit": {
            "limit_reached": False,
            "primary_window": {"used_percent": 12, "limit_window_seconds": 18000, "reset_at": 1_800_000_000},
            "secondary_window": {"used_percent": 3, "limit_window_seconds": 604800, "reset_at": 1_800_500_000}}})
        self.assertEqual(got["plan"], "plus")
        self.assertEqual({k: (w["label"], w["u"]) for k, w in got["windows"].items()},
                         {"primary": ("5-hour", 12.0), "secondary": ("Weekly", 3.0)})
        self.assertEqual(server.parse_ts(got["windows"]["primary"]["resets_at"]), 1_800_000_000)
        self.assertEqual(server.parse_codex_usage({"rate_limit": None})["windows"], {})
        with self.assertRaises(RuntimeError):
            server.parse_codex_usage([])

    def test_window_labels(self):
        self.assertEqual([server.codex_window(1, None, s)["label"] for s in (2592000, 172800, 7200, 61, None)],
                         ["Monthly", "2-day", "2-hour", "Limit", "Limit"])

    def test_reads_latest_reading_from_session_logs(self):
        home = Path(tempfile.mkdtemp())
        day = home / "sessions" / "2026" / "11" / "25"
        day.mkdir(parents=True)

        def ev(ts, rl):
            return json.dumps({"timestamp": ts, "type": "event_msg", "payload": {"type": "token_count", "rate_limits": rl}})
        codex = {"limit_id": "codex", "plan_type": "go", "rate_limit_reached_type": None,
                 "primary": {"used_percent": 20.0, "window_minutes": 43200, "resets_at": 1_797_604_471}, "secondary": None}
        (day / "rollout-a.jsonl").write_text("\n".join([
            ev("2026-11-25T10:00:00.000Z", codex),
            ev("2026-11-25T10:01:00.000Z", {**codex, "limit_id": "other", "primary": {"used_percent": 99.0}}),
            ev("2026-11-25T10:02:00.000Z", None),
            "not json"]) + "\n")
        with mock.patch.object(server, "CODEX_HOME", home):
            at, usage = server.codex_session_reading()
            self.assertEqual(at, datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc).timestamp())
            self.assertEqual(usage["windows"]["primary"]["u"], 20.0)
            self.assertEqual(usage["windows"]["primary"]["label"], "Monthly")
            self.assertNotIn("secondary", usage["windows"])
        with mock.patch.object(server, "CODEX_HOME", home / "missing"):
            self.assertIsNone(server.codex_session_reading())

    def test_reads_token_only_while_valid(self):
        home = Path(tempfile.mkdtemp())

        def write(exp):
            claims = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
            (home / "auth.json").write_text(json.dumps({"tokens": {"access_token": f"h.{claims}.s", "account_id": "acct"}}))
        with mock.patch.object(server, "CODEX_HOME", home):
            self.assertEqual(server.read_codex_auth(), (None, None))
            write(time.time() + 3600)
            self.assertEqual(server.read_codex_auth()[1], "acct")
            self.assertTrue(server.read_codex_auth()[0].startswith("h."))
            write(time.time() + 30)
            self.assertEqual(server.read_codex_auth(), (None, "acct"))


class AuthUnitTests(unittest.TestCase):
    def setUp(self):
        server.SESSIONS.clear()
        server.DEVICES.clear()

    def test_session_roundtrip_and_tamper(self):
        s = server.make_session()
        self.assertTrue(server.session_valid(s))
        exp, nonce, sig = s.split(".")
        self.assertFalse(server.session_valid(f"{int(exp) + 1}.{nonce}.{sig}"))  # extended expiry
        self.assertFalse(server.session_valid(f"{exp}.{nonce}.{'0' * 64}"))
        for bad in ("", "a.b.c", "\u00b2.a.b", "9" * 5000 + ".a.b", "1.a.\u00e9"):
            self.assertFalse(server.session_valid(bad))  # never raises

    def test_session_expires(self):
        s = server.make_session(now=time.time() - server.SESSION_DAYS * 86400 - 5)
        self.assertFalse(server.session_valid(s))

    def test_changing_password_invalidates_sessions(self):
        s = server.make_session()
        with mock.patch.object(server, "MASTER_PASSWORD", "another-password-123"):
            self.assertFalse(server.session_valid(s))

    def test_logout_revokes_server_side(self):
        token = server.make_session()
        server.SESSIONS.remove(server.session_nonce(token))
        self.assertFalse(server.session_valid(token))

    def test_device_tokens_are_revocable(self):
        d = server.make_device()
        self.assertIsNotNone(server.device_id(d))
        server.DEVICES.clear()
        self.assertIsNone(server.device_id(d))

    def test_password_check(self):
        self.assertTrue(server.password_ok(PASSWORD))
        for bad in ("", PASSWORD + "x", PASSWORD.upper(), None, 123, ["x"], "x" * 5000):
            self.assertFalse(server.password_ok(bad))

    def test_per_ip_limit(self):
        lim, t = server.LoginLimiter(), 1000.0
        for _ in range(server.LOGIN_MAX_FAILS):
            self.assertEqual(lim.retry_after("ip:1.2.3.4", True, now=t), 0)
            lim.fail("ip:1.2.3.4", True, now=t)
        self.assertGreater(lim.retry_after("ip:1.2.3.4", True, now=t), 0)
        self.assertEqual(lim.retry_after("ip:5.6.7.8", False, now=t), 0)  # other IPs unaffected
        self.assertEqual(lim.retry_after("ip:1.2.3.4", True, now=t + server.LOGIN_WINDOW + 1), 0)

    def test_global_limit_spares_local_logins(self):
        lim, t = server.LoginLimiter(), 1000.0
        for i in range(server.GLOBAL_MAX_FAILS):  # botnet: one failure per IP
            lim.fail(f"ip:10.0.{i // 250}.{i % 250}", True, now=t)
        self.assertGreater(lim.retry_after("ip:9.9.9.9", True, now=t), 0)  # internet locked
        self.assertEqual(lim.retry_after("local", False, now=t), 0)       # SSH tunnel still works

    def test_rate_buckets(self):
        self.assertEqual(server.rate_bucket(False, None, None), "local")
        self.assertEqual(server.rate_bucket(False, "203.0.113.5", None), "local")  # local listener ignores XFF
        a = server.rate_bucket(True, "2001:db8:1:2::1", None)
        self.assertEqual(a, server.rate_bucket(True, "2001:db8:1:2:ffff::9", None))  # same IPv6 /64
        self.assertNotEqual(a, server.rate_bucket(True, "2001:db8:1:3::1", None))
        self.assertEqual(server.rate_bucket(True, None, None), "ip:unknown")
        self.assertEqual(server.rate_bucket(True, "203.0.113.5", "dev1"), "device:dev1")

    def test_config_check_rejects_weak_settings(self):
        with mock.patch.multiple(server, MASTER_PASSWORD="change-me", SESSION_SECRET="short"):
            self.assertEqual(len(server.check_config()), 2)
        with mock.patch.object(server, "MASTER_PASSWORD", "only-15-chars!!"):
            self.assertEqual(len(server.check_config()), 1)
        with mock.patch.object(server, "BIND", "0.0.0.0"):
            self.assertEqual(len(server.check_config()), 1)
        with mock.patch.object(server, "PUBLIC_PORT", 0):
            self.assertEqual(len(server.check_config()), 1)  # domain without a proxy listener
        with mock.patch.object(server, "PUBLIC_HOSTS", {"localhost"}):
            self.assertEqual(len(server.check_config()), 1)
        with mock.patch.object(server, "ENV_PROBLEMS", ["world-readable .env"]):
            self.assertEqual(len(server.check_config()), 1)
        self.assertEqual(server.check_config(), [])

    def test_log_escapes_control_characters(self):
        buf = io.StringIO()
        with mock.patch.object(server.sys, "stderr", buf):
            server.log("evil\x1b[2J\nlogin ok from 1.2.3.4")
        out = buf.getvalue()
        self.assertEqual(out.count("\n"), 1)
        self.assertNotIn("\x1b", out)

    def test_secrets_not_inherited_by_child_processes(self):
        self.assertNotIn("MASTER_PASSWORD", os.environ)
        self.assertNotIn("SESSION_SECRET", os.environ)


class HttpBase(FakeVMMixin, unittest.TestCase):
    """Both real listeners on random ports, with claude-account and the usage API faked."""

    @classmethod
    def setUpClass(cls):
        cls.local = server.Server(("127.0.0.1", 0), server.Handler)
        cls.public = server.Server(("127.0.0.1", 0), server.Handler, public=True)
        for srv in (cls.local, cls.public):
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.local.shutdown()
        cls.public.shutdown()

    def setUp(self):
        super().setUp()
        server.LIMITER = server.LoginLimiter()
        server.ACTION_GATE["t"] = 0.0
        server.SESSIONS.clear()
        server.DEVICES.clear()

    def req(self, method, path, body=None, headers=None, host=None, public=False):
        srv = self.public if public else self.local
        port = srv.server_address[1]
        h = {"Host": host or (DOMAIN if public else f"127.0.0.1:{port}")}
        if body is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request(method, path, body=None if body is None else json.dumps(body), headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r, data

    def login(self, password=PASSWORD, headers=None, public=False):
        return self.req("POST", "/api/login", {"password": password}, headers, public=public)

    def cookies_from(self, resp):
        return {c.split("=", 1)[0]: c.split(";")[0] for c in resp.headers.get_all("Set-Cookie") or []}

    def cookie_from(self, resp):
        return next(v for k, v in self.cookies_from(resp).items() if k.endswith("cas_session"))


class HttpTests(HttpBase):
    def test_unauthenticated_gets_login_page_only(self):
        r, body = self.req("GET", "/")
        self.assertEqual(r.status, 200)
        self.assertIn(b"Master password", body)
        self.assertNotIn(b"example.com", body)
        r, _ = self.req("GET", "/api/accounts")
        self.assertEqual(r.status, 401)
        for path, payload in (("/api/use", {"name": "backup"}), ("/api/auto", {"enabled": False}),
                              ("/api/check", {}), ("/api/logout-all", {}),
                              ("/api/codex/use", {"name": "spare"}), ("/api/codex/auto", {"enabled": False})):
            r, _ = self.req("POST", path, payload)
            self.assertEqual(r.status, 401, path)
        self.assertEqual(self.uses(), [])
        self.assertEqual([c for c in self.vm.calls if c[0] == "codex-use"], [])

    def test_codex_switch_and_auto_toggle(self):
        cookie = self.cookie_from(self.login()[0])
        self.auto.tick()  # read both accounts' usage first
        r, body = self.req("POST", "/api/codex/use", {"name": "spare"}, headers={"Cookie": cookie})
        self.assertEqual(r.status, 200)
        d = json.loads(body)
        self.assertEqual([a["name"] for a in d["codex"]["accounts"] if a["active"]], ["spare"])
        self.assertEqual(self.vm.active, "main")  # Claude untouched
        self.assertFalse(self.auto.codex_enabled)  # moved off the preferred account by hand
        server.ACTION_GATE["t"] = 0.0
        r, body = self.req("POST", "/api/codex/use", {"name": "nope"}, headers={"Cookie": cookie})
        self.assertEqual(r.status, 400)
        server.ACTION_GATE["t"] = 0.0
        r, body = self.req("POST", "/api/codex/use", {"name": "../x"}, headers={"Cookie": cookie})
        self.assertEqual(r.status, 400)
        server.ACTION_GATE["t"] = 0.0
        r, body = self.req("POST", "/api/codex/auto", {"enabled": True}, headers={"Cookie": cookie})
        self.assertEqual(r.status, 200)
        self.assertTrue(json.loads(body)["codex"]["auto"]["enabled"])
        self.assertTrue(self.auto.enabled)

    def test_login_flow(self):
        r, _ = self.login("wrong-password")
        self.assertEqual(r.status, 401)
        self.assertIsNone(r.getheader("Set-Cookie"))
        r, _ = self.login()
        self.assertEqual(r.status, 200)
        sc = next(c for c in r.headers.get_all("Set-Cookie") if c.startswith("cas_session="))
        for attr in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(attr, sc)
        cookie = self.cookie_from(r)
        r, body = self.req("GET", "/api/accounts", headers={"Cookie": cookie})
        self.assertEqual(r.status, 200)
        self.assertEqual(len(json.loads(body)["accounts"]), 2)
        self.assertIn("codex", json.loads(body))
        r, body = self.req("GET", "/", headers={"Cookie": cookie})
        self.assertIn(b"Auto-switch", body)
        r, _ = self.req("POST", "/api/use", {"name": "backup"}, headers={"Cookie": cookie})
        self.assertEqual(r.status, 200)
        self.assertEqual(self.uses(), ["backup"])

    def test_public_listener_sets_secure_host_cookies_and_hsts(self):
        r, _ = self.login(headers=internet("203.0.113.9"), public=True)
        self.assertEqual(r.status, 200)
        self.assertEqual(set(self.cookies_from(r)), {"__Host-cas_session", "__Host-cas_device"})
        for c in r.headers.get_all("Set-Cookie"):
            self.assertIn("Secure", c)
        self.assertIn("max-age", r.getheader("Strict-Transport-Security"))
        cookie = self.cookie_from(r)
        r, _ = self.req("GET", "/api/accounts", headers={"Cookie": cookie, **internet("203.0.113.9")}, public=True)
        self.assertEqual(r.status, 200)

    def test_forged_cookie_rejected(self):
        r, _ = self.req("GET", "/api/accounts", headers={"Cookie": "cas_session=9999999999.abc.deadbeef"})
        self.assertEqual(r.status, 401)

    def test_bruteforce_lockout(self):
        hdr = internet("198.51.100.7")
        for _ in range(server.LOGIN_MAX_FAILS):
            self.assertEqual(self.login("nope", hdr, public=True)[0].status, 401)
        r, _ = self.login(PASSWORD, hdr, public=True)  # even the right password is refused while locked
        self.assertEqual(r.status, 429)
        self.assertTrue(r.getheader("Retry-After"))
        self.assertEqual(self.login(PASSWORD, internet("198.51.100.8"), public=True)[0].status, 200)

    def test_xff_spoofing_cannot_dodge_lockout(self):
        # The proxy appends the real client last; a client-supplied first hop is ignored.
        for i in range(server.LOGIN_MAX_FAILS):
            self.login("nope", internet(f"1.1.1.{i}, 198.51.100.20"), public=True)
        self.assertEqual(self.login(PASSWORD, internet("7.7.7.7, 198.51.100.20"), public=True)[0].status, 429)

    def test_local_listener_shares_one_bucket_and_ignores_xff(self):
        for i in range(server.LOGIN_MAX_FAILS):  # rotating fake XFF on the local port changes nothing
            self.login("nope", {"X-Forwarded-For": f"10.9.9.{i}"})
        self.assertEqual(self.login(PASSWORD)[0].status, 429)

    def test_host_allowlists_per_listener(self):
        self.assertEqual(self.req("GET", "/", host="evil.example.net")[0].status, 421)
        self.assertEqual(self.req("GET", "/", host=DOMAIN)[0].status, 421)                # domain never on local
        self.assertEqual(self.req("GET", "/", headers=internet("203.0.113.4"), host="localhost",
                                  public=True)[0].status, 421)                           # localhost never on public
        self.assertEqual(self.req("GET", "/", headers=internet("203.0.113.4"), public=True)[0].status, 200)

    def test_cross_origin_and_non_json_posts_refused(self):
        cookie = self.cookie_from(self.login()[0])
        r, _ = self.req("POST", "/api/use", {"name": "backup"},
                        headers={"Cookie": cookie, "Origin": "https://evil.example.net"})
        self.assertEqual(r.status, 403)
        port = self.local.server_address[1]
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/api/use", body="name=backup", headers={
            "Host": f"127.0.0.1:{port}", "Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(c.getresponse().status, 415)
        c.close()
        self.assertEqual(self.uses(), [])

    def test_security_headers_and_csp_nonce(self):
        r, body = self.req("GET", "/")
        csp = r.getheader("Content-Security-Policy")
        nonce = csp.split("'nonce-")[1].split("'")[0]
        self.assertIn(f'<script nonce="{nonce}">'.encode(), body)
        self.assertNotIn("unsafe-inline", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(r.getheader("Cache-Control"), "no-store")
        self.assertIn("noindex", r.getheader("X-Robots-Tag"))
        self.assertIsNone(r.getheader("Server"))
        _, body2 = self.req("GET", "/")
        self.assertNotEqual(body, body2)  # fresh nonce per response


class HttpHardeningTests(HttpBase):
    """Attacks found by the red-team reviews, kept as regression tests."""

    def test_plain_http_on_public_listener_is_refused(self):
        r, _ = self.login(headers={"X-Forwarded-For": "203.0.113.1", "X-Forwarded-Proto": "http"}, public=True)
        self.assertEqual(r.status, 403)
        self.assertIsNone(r.getheader("Set-Cookie"))
        r, _ = self.login(headers={"X-Forwarded-For": "203.0.113.1"}, public=True)  # no proto header at all
        self.assertEqual(r.status, 403)
        r, _ = self.req("GET", "/", headers={"X-Forwarded-For": "203.0.113.1"}, public=True)
        self.assertEqual(r.status, 308)
        self.assertEqual(r.getheader("Location"), f"https://{DOMAIN}/")

    def test_plain_cookie_not_accepted_on_public_listener(self):
        cookie = self.cookie_from(self.login()[0])  # local login -> non-Secure cookie
        r, _ = self.req("GET", "/api/accounts", headers={"Cookie": cookie, **internet("203.0.113.2")}, public=True)
        self.assertEqual(r.status, 401)

    def test_logout_and_logout_all_revoke_cookies_and_devices(self):
        r1 = self.login(headers=internet("203.0.113.30"), public=True)[0]
        device = self.cookies_from(r1)["__Host-cas_device"]
        c1 = self.cookie_from(self.login()[0])
        c2 = self.cookie_from(self.login()[0])
        self.req("POST", "/api/logout", {}, headers={"Cookie": c1})
        self.assertEqual(self.req("GET", "/api/accounts", headers={"Cookie": c1})[0].status, 401)  # replay fails
        self.assertEqual(self.req("GET", "/api/accounts", headers={"Cookie": c2})[0].status, 200)
        self.req("POST", "/api/logout-all", {}, headers={"Cookie": c2})
        self.assertEqual(self.req("GET", "/api/accounts", headers={"Cookie": c2})[0].status, 401)
        self.assertIsNone(server.device_id(device.split("=", 1)[1]))  # remembered browsers forgotten too

    def test_known_device_survives_global_lockout(self):
        r, _ = self.login(headers=internet("203.0.113.50"), public=True)
        device = self.cookies_from(r)["__Host-cas_device"]
        for i in range(server.GLOBAL_MAX_FAILS):  # botnet: one guess per address
            self.login("nope", internet(f"192.0.2.{i + 1}"), public=True)
        self.assertEqual(self.login(PASSWORD, internet("198.51.100.77"), public=True)[0].status, 429)  # strangers
        r, _ = self.login(PASSWORD, internet("198.51.100.78", Cookie=device), public=True)            # owner's browser
        self.assertEqual(r.status, 200)
        self.assertEqual(self.login(PASSWORD)[0].status, 200)                                           # SSH tunnel

    def test_garbage_cookies_do_not_crash(self):
        for value in ('"1.a.\u00e9"', '"\u00b2.a.b"', "9" * 5000 + ".a.b"):
            r, _ = self.req("GET", "/api/accounts", headers={"Cookie": f"cas_session={value}"})
            self.assertEqual(r.status, 401, value[:10])
            r, _ = self.login("nope", headers={"Cookie": f"cas_device={value}"})
            self.assertEqual(r.status, 401)

    def test_actions_are_throttled(self):
        cookie = self.cookie_from(self.login()[0])
        self.assertEqual(self.req("POST", "/api/check", {}, headers={"Cookie": cookie})[0].status, 200)
        self.assertEqual(self.req("POST", "/api/check", {}, headers={"Cookie": cookie})[0].status, 429)

    def test_healthz_local_only(self):
        self.assertEqual(self.req("GET", "/healthz")[0].status, 200)
        self.assertEqual(self.req("GET", "/healthz", headers=internet("203.0.113.3"), public=True)[0].status, 404)

    def test_slow_clients_on_public_listener_cannot_block_local(self):
        """Fill every public slot with slow-loris sockets: the local listener still answers,
        and the stalled sockets are cut off at the request deadline."""
        port = self.public.server_address[1]
        with mock.patch.object(server, "REQUEST_DEADLINE", 0.5):
            socks = []
            for _ in range(server.MAX_CONNECTIONS + 3):
                s = socket.create_connection(("127.0.0.1", port), timeout=5)
                s.sendall(b"POST /api/login HTTP/1.1\r\nHost: " + DOMAIN.encode() + b"\r\nContent-Length: 4096\r\n")
                socks.append(s)
            t0 = time.time()
            self.assertEqual(self.req("GET", "/healthz")[0].status, 200)  # local listener unaffected
            self.assertLess(time.time() - t0, 2)
            time.sleep(1.0)
            closed = 0
            for s in socks:
                try:
                    s.settimeout(0.5)
                    closed += s.recv(1) == b""
                except OSError:
                    closed += 1
                s.close()
            self.assertEqual(closed, len(socks))  # all cut off (deadline) or dropped (slots full)
        time.sleep(0.3)
        self.assertEqual(self.req("GET", "/", headers=internet("203.0.113.5"), public=True)[0].status, 200)


if __name__ == "__main__":
    unittest.main()
