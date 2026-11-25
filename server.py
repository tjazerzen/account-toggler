#!/usr/bin/env python3
"""Tiny web UI + auto-switcher for which Claude subscription Claude Code uses, and
which ChatGPT account Codex uses.

Switching always goes through `claude-account use <name>` / `codex-account use <name>`;
this server never writes credential files. For auto-switching it *reads* each account's current OAuth access
token (live file for the active account, saved profile for the others) only to ask
Anthropic's usage endpoint how much of the 5-hour / weekly limits are used. Tokens
stay in memory: they are never logged, stored, or sent anywhere but api.anthropic.com.
It never refreshes tokens itself (Claude Code does that), so it can't break a login.
Codex is tracked the same way: its own session logs first (no request), then each
account's access token (live ~/.codex/auth.json for the active one, the saved
~/.codex-accounts/<name>/auth.json for the others) only for chatgpt.com's usage endpoint.

Every page and API call needs the master password (MASTER_PASSWORD). Configuration
comes from the environment, or from `.env` next to this file; see `.env.example`.
Never commit `.env`.
"""
import base64
import functools
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
HOME = Path.home()
# Escape control characters so nothing a client sends can forge or garble log lines.
_CTRL = str.maketrans({c: f"\\x{c:02x}" for c in [*range(0x20), *range(0x7f, 0xa0)]})


def log(msg):
    sys.stderr.write(str(msg).translate(_CTRL) + "\n")
    sys.stderr.flush()


ENV_PROBLEMS = []


def load_env_file(path):
    """Minimal .env reader (KEY=VALUE, # comments, optional quotes). Real env wins."""
    try:
        st = path.stat()
        lines = path.read_text().splitlines()
    except OSError:
        return
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        ENV_PROBLEMS.append(f"{path} is accessible by other users; run: chmod 600 {path}")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = (s.strip() for s in line.split("=", 1))
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ.setdefault(key, value)


load_env_file(Path(os.environ.get("ENV_FILE", HERE / ".env")))

BIND = os.environ.get("BIND", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8765"))
CLI = os.environ.get("CLAUDE_ACCOUNT_BIN", str(HOME / ".local/bin/claude-account"))
PRIORITY = [s.strip() for s in os.environ.get("PRIORITY", "").split(",") if s.strip()]
THRESHOLD = float(os.environ.get("THRESHOLD", "90"))
POLL = int(os.environ.get("POLL_SECONDS", "60"))
INACTIVE_POLL = int(os.environ.get("INACTIVE_POLL_SECONDS", "300"))
MAX_BACKOFF = 600  # longest pause after Anthropic rate-limits the usage check (HTTP 429)
COOLDOWN = int(os.environ.get("COOLDOWN_SECONDS", "180"))
def default_state_dir(home):
    """State moved from ~/.local/state/claude-account-ui when the tool was renamed; an
    install that still only has the old folder keeps using it."""
    new, old = home / ".local/state/account-toggler", home / ".local/state/claude-account-ui"
    return old if not new.exists() and old.exists() else new


STATE_FILE = Path(os.environ.get("STATE_FILE", default_state_dir(HOME) / "state.json"))
SESSIONS_FILE = Path(os.environ.get("SESSIONS_FILE", STATE_FILE.parent / "sessions.json"))
DEVICES_FILE = Path(os.environ.get("DEVICES_FILE", STATE_FILE.parent / "devices.json"))
LOOPBACK_NAMES = {"127.0.0.1", "localhost", "::1"}
# Two listeners, each with its own connection pool:
#  PORT        local only (this machine / SSH tunnel). Loopback Host names, proxy headers ignored.
#  PUBLIC_PORT for the reverse proxy only. Only ALLOWED_HOSTS; every request is treated as coming
#              from the internet: HTTPS required, client IP from X-Forwarded-For, global lockout.
PUBLIC_PORT = int(os.environ.get("PUBLIC_PORT", "0") or 0)
PUBLIC_HOSTS = {h.strip().lower() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()}
SESSION_DAYS = float(os.environ.get("SESSION_DAYS", "14"))
DEVICE_DAYS = 365
MIN_PASSWORD_LEN = 20
LOGIN_MAX_FAILS = int(os.environ.get("LOGIN_MAX_FAILS", "5"))
LOGIN_WINDOW = int(os.environ.get("LOGIN_WINDOW_SECONDS", "900"))
# Across ALL internet clients: after this many wrong passwords per hour, internet logins
# lock for the rest of that hour. Browsers that signed in before (device cookie) and the
# SSH tunnel are exempt, so an attacker can't lock the owner out.
GLOBAL_MAX_FAILS = int(os.environ.get("GLOBAL_MAX_FAILS", "20"))
GLOBAL_WINDOW = 3600
FAIL_DELAY = 1.0          # seconds added to every wrong password
ACTION_INTERVAL = 2.0     # min seconds between switch / toggle / check calls
MAX_CONNECTIONS = 64      # concurrent connections per listener; extra ones are dropped
REQUEST_DEADLINE = 8.0    # seconds to receive a complete request before the socket is closed
# Secrets are read once and removed from the environment so that child processes
# (claude-account, and whatever it runs) never inherit them.
MASTER_PASSWORD = os.environ.pop("MASTER_PASSWORD", "")
SESSION_SECRET = os.environ.pop("SESSION_SECRET", "")
PLACEHOLDERS = {"", "change-me", "changeme"}

ACC_DIR = HOME / ".claude-accounts"
LIVE = HOME / ".claude" / ".credentials.json"
CLAUDE_CFG = HOME / ".claude.json"  # Claude Code caches its own usage reading here
USAGE_URL = "https://api.anthropic.com/api/oauth/usage"
WINDOWS = {"five_hour": "5-hour", "seven_day": "Weekly",
           "seven_day_opus": "Weekly (Opus)", "seven_day_sonnet": "Weekly (Sonnet)"}

SCOPED_KEYS = {"weekly": "seven_day", "session": "five_hour"}
SCOPED_LABELS = {"weekly": "Weekly", "session": "5-hour"}

CODEX_HOME = Path(os.environ.get("CODEX_HOME") or HOME / ".codex")
CODEX_CLI = os.environ.get("CODEX_ACCOUNT_BIN", str(HOME / ".local/bin/codex-account"))
CODEX_ACC_DIR = Path(os.environ.get("CODEX_ACCOUNTS_DIR") or HOME / ".codex-accounts")
CODEX_PRIORITY = [s.strip() for s in os.environ.get("CODEX_PRIORITY", "").split(",") if s.strip()]
CODEX_USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"  # what Codex's /status reads
CODEX_WINDOWS = {18000: "5-hour", 604800: "Weekly", 2592000: "Monthly"}

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
# "* main       someone@example.com  [max / default_claude_max_20x]"
LIST_RE = re.compile(r"^([* ]) (\S+)\s+(\S+)\s+\[(.*)\]\s*$")
SECRET_RE = re.compile(
    r"sk-ant-[A-Za-z0-9_-]+"
    r"|\"(?:accessToken|refreshToken|idToken|access_token|refresh_token|id_token)\"\s*:\s*\"[^\"]*\""
)
LOCK = threading.RLock()  # one claude-/codex-account invocation / auto-switch decision at a time
INDEX_HTML = (HERE / "index.html").read_bytes()
LOGIN_HTML = (HERE / "login.html").read_bytes()


def redact(text):
    return SECRET_RE.sub("[redacted]", text)


def atomic_write_json(path, obj):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ---------------------------------------------------------------- auth

_EPHEMERAL_SECRET = secrets.token_hex(32)
# Fixed for compatibility (the tool's old name): every session and device cookie key is
# derived from it, so changing it signs every browser out. Same for the cookie names
# (cas_session, cas_device) and the HMAC labels below.
_PASSWORD_SALT = b"claude-account-ui/password-v1"


def _scrypt(password):
    """Deliberately slow, memory-hard password hash (~16 MiB, tens of ms per guess)."""
    return hashlib.scrypt(password.encode("utf-8", "replace"), salt=_PASSWORD_SALT,
                          n=2 ** 14, r=8, p=1, dklen=32)


@functools.lru_cache(maxsize=2)
def _master_digest(master):
    return _scrypt(master)


def _key(label):
    # Bound to the password too: changing either one invalidates every cookie.
    secret = SESSION_SECRET or _EPHEMERAL_SECRET
    return hmac.new(secret.encode(), label + _master_digest(MASTER_PASSWORD), hashlib.sha256).digest()


def _make_token(label, days, now=None):
    exp = int((now or time.time()) + days * 86400)
    nonce = secrets.token_urlsafe(16)
    sig = hmac.new(_key(label), f"{exp}.{nonce}".encode(), hashlib.sha256).hexdigest()
    return f"{exp}.{nonce}.{sig}", nonce, exp


def _token_nonce(label, value, now=None):
    """Nonce of a valid, unexpired signed token "<exp>.<nonce>.<sig>", else None."""
    parts = (value or "").split(".")
    if len(parts) != 3 or not re.fullmatch(r"[0-9]{1,12}", parts[0]) or int(parts[0]) <= (now or time.time()):
        return None
    good = hmac.new(_key(label), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(parts[2].encode("utf-8", "replace"), good.encode()):
        return None
    return parts[1]


class SessionStore:
    """Server-side list of live tokens (hashed ids only), so sign-out really revokes."""

    def __init__(self, path, keep=50):
        self.path, self.keep, self.lock = path, keep, threading.Lock()
        try:
            data = json.loads(path.read_text())
            self.ids = {k: v for k, v in data.items() if isinstance(v, (int, float)) and v > time.time()}
        except (OSError, ValueError, AttributeError):
            self.ids = {}

    @staticmethod
    def _h(nonce):
        return hashlib.sha256(nonce.encode()).hexdigest()

    def _save(self):
        try:
            atomic_write_json(self.path, self.ids)
        except OSError as e:
            log(f"could not save sessions: {e.strerror}")

    def add(self, nonce, exp):
        with self.lock:
            now = time.time()
            self.ids = {k: v for k, v in self.ids.items() if v > now}
            while len(self.ids) >= self.keep:  # keep only the newest ones
                self.ids.pop(min(self.ids, key=self.ids.get))
            self.ids[self._h(nonce)] = exp
            self._save()

    def has(self, nonce, now=None):
        with self.lock:
            exp = self.ids.get(self._h(nonce))
            return exp is not None and exp > (now or time.time())

    def remove(self, nonce):
        with self.lock:
            if self.ids.pop(self._h(nonce), None) is not None:
                self._save()

    def clear(self):
        with self.lock:
            self.ids = {}
            self._save()


SESSIONS = SessionStore(SESSIONS_FILE)
DEVICES = SessionStore(DEVICES_FILE, keep=20)


def make_session(now=None):
    token, nonce, exp = _make_token(b"session-v2:", SESSION_DAYS, now)
    SESSIONS.add(nonce, exp)
    return token


def session_nonce(value, now=None):
    nonce = _token_nonce(b"session-v2:", value, now)
    return nonce if nonce and SESSIONS.has(nonce, now) else None


def session_valid(value, now=None):
    return session_nonce(value, now) is not None


def make_device():
    token, nonce, exp = _make_token(b"device-v1:", DEVICE_DAYS)
    DEVICES.add(nonce, exp)
    return token


def device_id(value):
    nonce = _token_nonce(b"device-v1:", value)
    return nonce if nonce and DEVICES.has(nonce) else None


def password_ok(candidate):
    if not isinstance(candidate, str) or len(candidate) > 1024:
        return False
    return hmac.compare_digest(_scrypt(candidate), _master_digest(MASTER_PASSWORD))


def rate_bucket(public, forwarded_ip, device):
    """Key that wrong passwords are counted under."""
    if device:
        return "device:" + device       # a browser that signed in before: its own counter
    if not public:
        return "local"                  # everything on the local listener shares one counter
    try:
        addr = ipaddress.ip_address(forwarded_ip or "")
    except ValueError:
        return "ip:" + (forwarded_ip or "unknown")[:64]
    if addr.version == 6:
        return "net:" + str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return "ip:" + str(addr)


class LoginLimiter:
    """At most LOGIN_MAX_FAILS wrong passwords per bucket per LOGIN_WINDOW, and at most
    GLOBAL_MAX_FAILS per hour from the internet as a whole (defeats IP-rotating botnets)."""

    def __init__(self):
        self.fails, self.global_fails, self.lock = {}, [], threading.Lock()

    def retry_after(self, key, count_global, now=None):
        now = now or time.time()
        with self.lock:
            recent = [t for t in self.fails.get(key, []) if now - t < LOGIN_WINDOW]
            if recent:
                self.fails[key] = recent
            else:
                self.fails.pop(key, None)
            self.global_fails = [t for t in self.global_fails if now - t < GLOBAL_WINDOW]
            waits = [0]
            if len(recent) >= LOGIN_MAX_FAILS:
                waits.append(int(LOGIN_WINDOW - (now - recent[0])) + 1)
            if count_global and len(self.global_fails) >= GLOBAL_MAX_FAILS:
                waits.append(int(GLOBAL_WINDOW - (now - self.global_fails[0])) + 1)
            return max(waits)

    def fail(self, key, count_global, now=None):
        now = now or time.time()
        with self.lock:
            if len(self.fails) > 10000:  # bound memory under a distributed attack
                self.fails.clear()
            self.fails.setdefault(key, []).append(now)
            if count_global:
                self.global_fails.append(now)
                if len(self.global_fails) == GLOBAL_MAX_FAILS:
                    log(f"ALERT: {GLOBAL_MAX_FAILS} failed logins from the internet within an hour; "
                        "new internet logins locked for the rest of the hour")

    def reset(self, key):
        with self.lock:
            self.fails.pop(key, None)


LIMITER = LoginLimiter()
LOGIN_SLOTS = threading.BoundedSemaphore(4)  # concurrent password checks
ACTION_GATE = {"t": 0.0}
ACTION_LOCK = threading.Lock()


def action_allowed():
    with ACTION_LOCK:
        now = time.time()
        if now - ACTION_GATE["t"] < ACTION_INTERVAL:
            return False
        ACTION_GATE["t"] = now
        return True


# ---------------------------------------------------------------- claude-account + usage

def run(*args, cli=None):
    """Run claude-account (or codex-account); return (exit code, stdout, stderr), all redacted."""
    cli = cli or CLI
    tool = Path(cli).name
    try:
        p = subprocess.run([cli, *args], capture_output=True, text=True, timeout=60,
                           stdin=subprocess.DEVNULL)
        return p.returncode, redact(p.stdout), redact(p.stderr)
    except subprocess.TimeoutExpired:
        return 124, "", f"{tool} timed out"
    except OSError as e:
        return 127, "", f"could not run {tool}: {e.strerror}"


def plan_label(plan):
    m = re.search(r"max_(\d+x)", plan)
    if m:
        return f"Max {m.group(1)}"
    return plan.split("/")[0].strip().capitalize() or "?"


def list_accounts():
    code, out, err = run("list")
    if code:
        return {"accounts": [], "error": (err or out).strip() or f"claude-account list failed ({code})"}
    accounts = []
    for line in out.splitlines():
        m = LIST_RE.match(line)
        if m:
            star, name, email, plan = m.groups()
            accounts.append({"name": name, "email": email, "plan": plan.strip(),
                             "label": plan_label(plan), "active": star == "*"})
    return {"accounts": accounts, "error": None}


def read_oauth(path):
    """Return (access token if still valid else None, rateLimitTier). Never logs the token."""
    try:
        o = json.loads(Path(path).read_text()).get("claudeAiOauth") or {}
    except (OSError, ValueError, AttributeError):
        return None, None
    token = o.get("accessToken")
    valid = token and (o.get("expiresAt") or 0) / 1000 > time.time() + 60
    return (token if valid else None), o.get("rateLimitTier")


class RateLimited(RuntimeError):
    pass


def parse_windows(data):
    windows = {}
    for key in WINDOWS:
        w = data.get(key)
        if isinstance(w, dict) and w.get("utilization") is not None:
            windows[key] = {"u": float(w["utilization"]), "resets_at": w.get("resets_at")}
    # Model-scoped limits (e.g. a weekly Fable limit) only appear in `limits`.
    for lim in data.get("limits") or []:
        try:
            model = ((lim.get("scope") or {}).get("model") or {}).get("display_name")
            group = str(lim.get("group") or "")
            if not model or lim.get("percent") is None:
                continue
            key = SCOPED_KEYS.get(group, group) + "_" + re.sub(r"[^a-z0-9]+", "_", model.lower()).strip("_")
            if key not in windows:
                windows[key] = {"u": float(lim["percent"]), "resets_at": lim.get("resets_at"),
                                "label": f"{SCOPED_LABELS.get(group, group.title())} ({model})"}
        except (AttributeError, TypeError, ValueError):
            continue
    return windows


def fetch_usage(token):
    req = urllib.request.Request(USAGE_URL, headers={
        "Authorization": "Bearer " + token,
        "anthropic-beta": "oauth-2025-04-20",
        "User-Agent": "account-toggler/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimited("Anthropic rate-limited the usage check") from None
        raise RuntimeError(f"usage check failed (HTTP {e.code})") from None
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        raise RuntimeError(f"usage check failed ({type(e).__name__})") from None
    return parse_windows(data)


def claude_code_reading(names):
    """Claude Code's own last usage reading, from ~/.claude.json: (account name, fetched_at, windows).
    Matched to a profile by account UUID, so it is never attributed to the wrong account."""
    try:
        c = json.loads(CLAUDE_CFG.read_text()).get("cachedUsageUtilization") or {}
        uuid, fetched_at = c.get("accountUuid"), float(c["fetchedAtMs"]) / 1000
        windows = parse_windows(c.get("utilization") or {})
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    for n in names:
        try:
            if uuid and json.loads((ACC_DIR / n / "oauthAccount.json").read_text()).get("accountUuid") == uuid:
                return n, fetched_at, windows
        except (OSError, ValueError, AttributeError):
            continue
    return None


def parse_ts(iso):
    try:
        return datetime.fromisoformat(iso).timestamp() if iso else None
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------- Codex

def codex_window(used, resets_epoch, seconds):
    try:
        s = int(seconds or 0)
        resets = datetime.fromtimestamp(float(resets_epoch), timezone.utc).isoformat() if resets_epoch else None
    except (TypeError, ValueError, OverflowError, OSError):
        s, resets = 0, None
    label = CODEX_WINDOWS.get(s) or (f"{s // 86400}-day" if s and s % 86400 == 0
                                     else f"{s // 3600}-hour" if s and s % 3600 == 0 else "Limit")
    return {"u": float(used), "resets_at": resets, "label": label}


def list_codex_accounts():
    code, out, err = run("list", "--json", cli=CODEX_CLI)
    if code:
        return {"accounts": [], "error": (err or out).strip() or f"codex-account list failed ({code})"}
    try:
        rows = json.loads(out)
        accounts = [{"name": r["name"], "email": str(r.get("email") or "?"), "plan": str(r.get("plan") or "?"),
                     "label": str(r.get("plan") or "?").replace("_", " ").title(), "active": r.get("active") is True}
                    for r in rows if isinstance(r, dict) and NAME_RE.match(str(r.get("name", "")))]
    except (ValueError, TypeError, KeyError):
        return {"accounts": [], "error": "codex-account list returned something unexpected"}
    return {"accounts": accounts, "error": None}


def codex_auth_path(name, active):
    return CODEX_HOME / "auth.json" if name == active else CODEX_ACC_DIR / name / "auth.json"


def read_codex_auth(path=None):
    """A Codex ChatGPT login: (access token if still valid else None, account id or None).
    Codex refreshes the token itself; this never writes or logs it."""
    try:
        t = json.loads(Path(path or CODEX_HOME / "auth.json").read_text()).get("tokens") or {}
        token, account = t.get("access_token"), t.get("account_id")
        claims = token.split(".")[1]
        exp = json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4))).get("exp") or 0
    except (OSError, ValueError, AttributeError, IndexError, TypeError):
        return None, None
    return (token if exp > time.time() + 60 else None), account or "?"


def parse_codex_usage(data):
    if not isinstance(data, dict):
        raise RuntimeError("Codex usage check returned something unexpected")
    rl = data.get("rate_limit") if isinstance(data.get("rate_limit"), dict) else {}
    windows = {}
    for key in ("primary", "secondary"):
        w = rl.get(key + "_window")
        if isinstance(w, dict) and w.get("used_percent") is not None:
            windows[key] = codex_window(w["used_percent"], w.get("reset_at"), w.get("limit_window_seconds"))
    return {"windows": windows, "plan": data.get("plan_type"), "email": data.get("email"),
            "limit_reached": bool(rl.get("limit_reached"))}


def fetch_codex_usage(token, account):
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json",
               "User-Agent": "account-toggler/1.0"}
    if account and account != "?":
        headers["ChatGPT-Account-Id"] = account
    try:
        with urllib.request.urlopen(urllib.request.Request(CODEX_USAGE_URL, headers=headers), timeout=10) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimited("ChatGPT rate-limited the Codex usage check") from None
        raise RuntimeError(f"Codex usage check failed (HTTP {e.code})") from None
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        raise RuntimeError(f"Codex usage check failed ({type(e).__name__})") from None
    return parse_codex_usage(data)


def _last_codex_reading(path, tail=512 * 1024):
    try:
        with open(path, "rb") as fh:
            fh.seek(max(0, fh.seek(0, os.SEEK_END) - tail))
            lines = fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        if '"rate_limits"' not in line:
            continue
        try:
            ev = json.loads(line)
            rl = ev["payload"]["rate_limits"]
            at = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00")).timestamp()
            if not isinstance(rl, dict) or rl.get("limit_id") not in (None, "codex"):
                continue
            windows = {k: codex_window(w["used_percent"], w.get("resets_at"), (w.get("window_minutes") or 0) * 60)
                       for k in ("primary", "secondary")
                       if isinstance(w := rl.get(k), dict) and w.get("used_percent") is not None}
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        return at, {"windows": windows, "plan": rl.get("plan_type"),
                    "limit_reached": bool(rl.get("rate_limit_reached_type"))}
    return None


def codex_session_reading(days=14):
    """Codex's own latest rate-limit reading, from the session logs it writes after every
    model reply: (when, usage) or None. Costs no request. The logs don't say which account
    a reading is for (a thread started on one account moves to the next after a switch),
    so the caller credits it to the account that was active at that time."""
    day_dirs = sorted((CODEX_HOME / "sessions").glob("[0-9]*/[0-9]*/[0-9]*"), reverse=True)[:days]
    files = []
    for d in day_dirs:
        for f in d.glob("rollout-*.jsonl"):
            try:
                files.append((f.stat().st_mtime, f))
            except OSError:
                pass
    readings = [r for _, f in sorted(files, reverse=True)[:3] if (r := _last_codex_reading(f))]
    return max(readings, key=lambda r: r[0], default=None)




class AutoSwitcher:
    """Polls usage and keeps the highest-priority account that is under THRESHOLD active."""

    def __init__(self):
        try:
            s = json.loads(STATE_FILE.read_text())
        except (OSError, ValueError):
            s = {}
        self.enabled = s.get("enabled", True)
        self.usage = s.get("usage", {})  # name -> {windows, fetched_at, error}
        self.codex_enabled = s.get("codex_enabled", True)
        self.codex_usage = s.get("codex_usage", {})  # name -> {windows, plan, fetched_at, source, error}
        self.codex_last_switch_at = s.get("codex_last_switch_at", 0)
        self.codex_last_active = s.get("codex_last_active")
        self.codex_active_since = s.get("codex_active_since", 0)  # when the active account went live
        self.events = s.get("events", [])[-50:]
        self.last_switch_at = s.get("last_switch_at", 0)
        self.last_active = s.get("last_active")
        self.last_check = 0
        self.wake = threading.Event()

    def save(self):
        try:
            atomic_write_json(STATE_FILE, {
                "enabled": self.enabled, "usage": self.usage, "events": self.events[-50:],
                "last_switch_at": self.last_switch_at, "last_active": self.last_active,
                "codex_enabled": self.codex_enabled, "codex_usage": self.codex_usage,
                "codex_last_switch_at": self.codex_last_switch_at, "codex_last_active": self.codex_last_active,
                "codex_active_since": self.codex_active_since})
        except OSError as e:
            log(f"could not save state: {e.strerror}")

    def event(self, msg, kind="info"):
        self.events.append({"t": time.time(), "msg": msg, "kind": kind})
        self.events = self.events[-50:]
        log(f"[{kind}] {msg}")

    def blocking(self, name, now, codex=False):
        """Limit windows of `name` that are at/over THRESHOLD and haven't reset yet."""
        hits = []
        usage = self.codex_usage if codex else self.usage
        for key, w in ((usage.get(name) or {}).get("windows") or {}).items():
            resets = parse_ts(w.get("resets_at"))
            if w["u"] >= THRESHOLD and (resets is None or resets > now):
                label = w.get("label") if codex else (WINDOWS.get(key) or w.get("label"))
                hits.append(f"{name} {label or key} limit at {w['u']:.0f}%")
        return hits

    def choose(self, names, active, now, codex=False):
        prio = CODEX_PRIORITY if codex else PRIORITY
        order = [n for n in prio if n in names] + [n for n in names if n not in prio]
        usage = self.codex_usage if codex else self.usage
        # While the active account has room, never move to one whose usage hasn't been read
        # yet (no reading isn't room). Once it's full, an unknown account beats staying put.
        settled = not self.blocking(active, now, codex) if active else False
        for n in order:
            if settled and n != active and not (usage.get(n) or {}).get("fetched_at"):
                continue
            if not self.blocking(n, now, codex):
                return n
        return active  # every account is near its limit: stay put rather than flip-flop

    def identity_problem(self, active, names):
        """Guard against overwriting a saved login: the live login's plan tier must match
        the active profile's (only checkable when the accounts have distinct tiers)."""
        tiers = {n: read_oauth(ACC_DIR / n / "credentials.json")[1] for n in names}
        live_tier = read_oauth(LIVE)[1]
        if None in tiers.values() or live_tier is None or len(set(tiers.values())) != len(tiers):
            return None
        if tiers.get(active) != live_tier:
            owner = next((n for n, t in tiers.items() if t == live_tier), "another account")
            return (f"The live login looks like '{owner}' but '{active}' is marked active. "
                    f"Switching now could overwrite the saved '{active}' login. "
                    f"Fix on the VM with: claude-account save {owner}")
        return None

    def manual_switch(self, target, names):
        """Called after a manual switch; pauses auto mode if it would undo the user's choice."""
        self.last_active = target
        if self.enabled and self.choose(names, target, time.time()) != target:
            self.enabled = False
            self.event(f"Auto-switch turned off because you switched to '{target}' manually. "
                       "Turn it back on to let it manage accounts again.")
        self.save()

    def refresh_usage(self, names, active, force):
        now = time.time()
        # Claude Code polls the same endpoint and caches the result. Using it costs no request.
        cc = claude_code_reading(names)
        if cc and cc[1] > (self.usage.get(cc[0], {}).get("fetched_at") or 0):
            self.usage.setdefault(cc[0], {}).update(windows=cc[2], fetched_at=cc[1], error=None)
        for n in names:
            u = self.usage.setdefault(n, {})
            due = POLL if n == active else INACTIVE_POLL
            if not force and (now - (u.get("checked_at") or 0) < due - 5
                              or now - (u.get("fetched_at") or 0) < due - 5
                              or now < (u.get("retry_at") or 0)):
                continue
            u["checked_at"] = now
            token, _ = read_oauth(LIVE if n == active else ACC_DIR / n / "credentials.json")
            if not token:
                u["error"] = "token expired; showing last known usage (resets are still honoured)"
                continue
            try:
                u.update(windows=fetch_usage(token), fetched_at=now, error=None, backoff=None, retry_at=None)
            except RateLimited as e:
                # The endpoint allows only a few calls per window, shared with Claude Code itself.
                u["backoff"] = min((u.get("backoff") or POLL) * 2, MAX_BACKOFF)
                u["retry_at"] = now + u["backoff"]
                u["error"] = f"{e}; retrying in {u['backoff'] // 60 or 1} min"
            except RuntimeError as e:
                u["error"] = str(e)

    def refresh_codex(self, names, active, force):
        now = time.time()
        logins = {n: read_codex_auth(codex_auth_path(n, active)) for n in names}
        seen = codex_session_reading()
        # Only readings written after the active account went live are its own. A reading
        # without windows (e.g. only a non-Codex limit) says nothing: it mustn't count as fresh,
        # or the endpoint would never be asked.
        if active and seen and seen[1].get("windows") and seen[0] > self.codex_active_since + 5:
            c = self.codex_usage.setdefault(active, {})
            if seen[0] > (c.get("fetched_at") or 0):
                c.update(seen[1], fetched_at=seen[0], source="Codex's session log", error=None)
        for n in names:
            c = self.codex_usage.setdefault(n, {})
            # While Codex is in use its log is fresh, so the endpoint is only asked when it's idle.
            if not force and (now - (c.get("checked_at") or 0) < INACTIVE_POLL - 5
                              or now - (c.get("fetched_at") or 0) < INACTIVE_POLL - 5
                              or now < (c.get("retry_at") or 0)):
                continue
            c["checked_at"] = now
            token, account = logins[n]
            if not token:
                c["error"] = (("Codex login token expired (Codex renews it when it next runs)" if n == active else
                               "saved login token expired (it renews once Codex uses this account again)")
                              + "; showing the last reading") if account else "no ChatGPT login found"
                continue
            try:
                c.update(fetch_codex_usage(token, account), fetched_at=now, source="ChatGPT",
                         error=None, backoff=None, retry_at=None)
            except RateLimited as e:
                c["backoff"] = min((c.get("backoff") or POLL) * 2, MAX_BACKOFF)
                c["retry_at"] = now + c["backoff"]
                c["error"] = f"{e}; retrying in {c['backoff'] // 60 or 1} min"
            except RuntimeError as e:
                c["error"] = str(e)

    def codex_manual_switch(self, target, names):
        self.codex_last_active, self.codex_active_since = target, time.time()
        if self.codex_enabled and self.choose(names, target, time.time(), codex=True) != target:
            self.codex_enabled = False
            self.event(f"Codex auto-switch turned off because Codex was switched to '{target}' by hand. "
                       "Turn it back on to let it manage Codex accounts again.")
        self.save()

    def sync_logins(self, cli, what):
        """Let the CLI pick up the live login: a new account is saved under a name from its
        email, a known one gets its saved copy refreshed. Returns the names it added."""
        code, out, err = run("sync", cli=cli)
        if code:
            log(f"{what} sync failed: {(err or out).strip()[:200]}")
            return set()
        added = set()
        for line in out.splitlines():
            m = re.match(r"Added '([A-Za-z0-9_.-]{1,64})': (.{0,200})$", line)
            if m:
                added.add(m.group(1))
                self.event(f"New {what} login found and saved as '{m.group(1)}': {m.group(2)}", "switch")
            elif line.startswith(("Updated", "Live login is")):
                log(f"{what} sync: {line}")
        return added

    def tick_codex(self, force):
        added = self.sync_logins(CODEX_CLI, "Codex")
        st = list_codex_accounts()
        if st["error"]:
            log(f"codex list failed: {st['error']}")
            return
        names = [a["name"] for a in st["accounts"]]
        active = next((a["name"] for a in st["accounts"] if a["active"]), None)
        if active in added:  # a fresh login, not a choice: auto-switch stays as it was
            self.codex_last_active, self.codex_active_since = active, time.time()
        if self.codex_last_active and active and active != self.codex_last_active:
            self.event(f"Codex account changed outside the switcher: {self.codex_last_active} → {active}")
            self.codex_manual_switch(active, names)
        if active != self.codex_last_active:
            self.codex_active_since = time.time()
        self.codex_last_active = active
        self.refresh_codex(names, active, force)
        now = time.time()
        if self.codex_enabled and active and len(names) > 1:
            target = self.choose(names, active, now, codex=True)
            if target != active and now - self.codex_last_switch_at >= COOLDOWN:
                why = "; ".join(self.blocking(active, now, True)) or f"'{target}' is preferred and has room again"
                code, out, err = run("use", target, cli=CODEX_CLI)
                if code == 0:
                    self.codex_last_switch_at, self.codex_last_active, self.codex_active_since = now, target, now
                    self.event(f"Codex auto-switched {active} → {target} ({why}).", "switch")
                else:
                    self.event(f"Codex auto-switch to '{target}' failed: {(err or out).strip()}", "error")

    def tick(self, force=False):
        with LOCK:
            try:
                self.tick_codex(force)
            except Exception as e:  # Codex trouble must never stop the Claude side
                log(f"codex tick crashed: {type(e).__name__}")
            added = self.sync_logins(CLI, "Claude")
            st = list_accounts()
            if st["error"]:
                log(f"list failed: {st['error']}")
                return
            names = [a["name"] for a in st["accounts"]]
            active = next((a["name"] for a in st["accounts"] if a["active"]), None)
            if active in added:  # a fresh login, not a choice: auto-switch stays as it was
                self.last_active = active
            if self.last_active and active and active != self.last_active:
                self.event(f"Account changed outside the auto-switcher: {self.last_active} → {active}")
                self.manual_switch(active, names)
            self.last_active = active
            self.refresh_usage(names, active, force)
            now = self.last_check = time.time()

            if self.enabled and active:
                target = self.choose(names, active, now)
                if target != active and now - self.last_switch_at >= COOLDOWN:
                    problem = self.identity_problem(active, names)
                    if problem:
                        self.enabled = False
                        self.event("Auto-switch paused. " + problem, "error")
                    else:
                        why = "; ".join(self.blocking(active, now)) or f"'{target}' is preferred and has room again"
                        code, out, err = run("use", target)
                        if code == 0:
                            self.last_switch_at, self.last_active = now, target
                            self.event(f"Auto-switched {active} → {target} ({why}).", "switch")
                        else:
                            self.event(f"Auto-switch to '{target}' failed: {(err or out).strip()}", "error")
            self.save()

    def loop(self):
        time.sleep(3)
        while True:
            try:
                self.tick()
            except Exception as e:  # keep the loop alive; never print tokens
                log(f"auto-switch tick crashed: {type(e).__name__}")
            self.wake.wait(POLL)
            self.wake.clear()

    def windows_view(self, windows, now, labels=None):
        items = sorted(windows.items()) if labels is None else windows.items()
        return [{"key": k, "label": (labels or {}).get(k) or w.get("label") or k, "u": w["u"],
                 "resets_at": w.get("resets_at"), "reset": (parse_ts(w.get("resets_at")) or now + 1) <= now}
                for k, w in items]

    def decorate(self, st, codex=None):
        now = time.time()
        for a in st["accounts"]:
            u = self.usage.get(a["name"]) or {}
            a["usage"] = {"windows": self.windows_view(u.get("windows") or {}, now, WINDOWS),
                          "fetched_at": u.get("fetched_at"), "error": u.get("error")}
            a["blocked"] = bool(self.blocking(a["name"], now))
        codex = codex if codex is not None else list_codex_accounts()
        for a in codex["accounts"]:
            c = self.codex_usage.get(a["name"]) or {}
            a["limit_reached"] = bool(c.get("limit_reached"))
            a["usage"] = {"windows": self.windows_view(c.get("windows") or {}, now),
                          "fetched_at": c.get("fetched_at"), "source": c.get("source"), "error": c.get("error")}
            a["blocked"] = bool(self.blocking(a["name"], now, codex=True))
        if not codex["error"] and codex["accounts"] and not any(a["active"] for a in codex["accounts"]):
            codex["error"] = ("Codex is signed in with a login that isn't saved (or not signed in). "
                              "On the VM: codex-account save <name>")
        st["codex"] = {**codex, "auto": {"enabled": self.codex_enabled,
                                         "priority": CODEX_PRIORITY or [a["name"] for a in codex["accounts"]]}}
        st["auto"] = {"enabled": self.enabled, "threshold": THRESHOLD, "priority": PRIORITY,
                      "poll": POLL, "last_check": self.last_check or None,
                      "events": list(reversed(self.events[-8:]))}
        return st


AUTO = AutoSwitcher()


def snapshot():
    with LOCK:
        return AUTO.decorate(list_accounts())


# ---------------------------------------------------------------- HTTP

class Server(ThreadingHTTPServer):
    """Threaded server with its own cap on concurrent connections. `public` marks the
    listener the reverse proxy talks to; the local one never trusts proxy headers."""
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address, handler, public=False):
        super().__init__(address, handler)
        self.public = public
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)  # full: drop instead of spawning more threads
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # One short line instead of a traceback, so junk connections can't flood the log.
        exc = sys.exc_info()[1]
        if not isinstance(exc, (BrokenPipeError, ConnectionResetError, TimeoutError)):
            log(f"request error from {client_address[0]}: {type(exc).__name__}")


class Handler(BaseHTTPRequestHandler):
    server_version = ""
    sys_version = ""
    timeout = 10  # per socket read

    # -- connection lifetime: the whole request must arrive within REQUEST_DEADLINE

    def setup(self):
        super().setup()
        self._deadline = threading.Timer(REQUEST_DEADLINE, self._kill)
        self._deadline.daemon = True
        self._deadline.start()

    def _kill(self):
        try:
            self.request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _request_received(self):
        self._deadline.cancel()

    def finish(self):
        self._deadline.cancel()
        super().finish()

    def send_response(self, code, message=None):
        # Same as the stdlib, minus the Server header: don't advertise what this is.
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def log_message(self, fmt, *args):
        log("%s %s" % (self.client_ip(), fmt % args))

    # -- who is asking

    @property
    def public(self):
        return getattr(self.server, "public", False)

    def peer(self):
        return self.client_address[0] if self.client_address else ""

    def forwarded_ip(self):
        """Real client IP as appended by our reverse proxy (last X-Forwarded-For hop)."""
        headers = getattr(self, "headers", None)
        if not self.public or headers is None:
            return None
        last = (headers.get("X-Forwarded-For") or "").split(",")[-1].strip()
        return last[:64] or None

    def client_ip(self):
        return self.forwarded_ip() or self.peer()

    def is_https(self):
        headers = getattr(self, "headers", None)
        return self.public and headers is not None and \
            (headers.get("X-Forwarded-Proto") or "").lower() == "https"

    def _hostname(self):
        try:
            return urlsplit("//" + (self.headers.get("Host") or "")).hostname
        except ValueError:
            return None

    def _host_ok(self):
        # Only answer for names this listener serves (blocks DNS rebinding and host scanners).
        return self._hostname() in (PUBLIC_HOSTS if self.public else LOOPBACK_NAMES)

    # -- cookies

    def _cookie(self, base):
        """Value of our cookie `base`; on the public listener only the __Host-/Secure variant counts."""
        try:
            jar = SimpleCookie(self.headers.get("Cookie") or "")
        except CookieError:
            return None
        names = ("__Host-" + base,) if self.public else ("__Host-" + base, base)
        for name in names:
            if name in jar:
                return jar[name].value
        return None

    def _set_cookie(self, base, value, max_age):
        if self.is_https():
            return f"__Host-{base}={value}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict"
        return f"{base}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict"

    def authed(self):
        return session_nonce(self._cookie("cas_session")) is not None

    # -- responses

    def _send(self, code, body, ctype, csp="default-src 'none'; frame-ancestors 'none'", headers=()):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        if self.is_https():
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Security-Policy", csp)
        for k, v in headers:
            if any(c in str(v) for c in "\r\n\0"):
                raise ValueError("refusing to send a header value with a line break")
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _json(self, code, obj, headers=()):
        self._send(code, json.dumps(obj), "application/json", headers=headers)

    def _page(self, template):
        nonce = secrets.token_urlsafe(16)
        body = (template.replace(b"<script>", f'<script nonce="{nonce}">'.encode())
                        .replace(b"<style>", f'<style nonce="{nonce}">'.encode()))
        csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
               "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self._send(200, body, "text/html; charset=utf-8", csp=csp)

    def _gate(self):
        """Common checks. Returns True if the request may proceed (else a reply was sent)."""
        if not self._host_ok():
            self._json(421, {"ok": False, "output": "unknown host"})
            return False
        if self.public and not self.is_https():
            # Never accept a password or cookie over plain HTTP from the internet.
            if self.command in ("GET", "HEAD"):
                # Redirect target comes from our own config, never from the request.
                host = next(h for h in sorted(PUBLIC_HOSTS) if h == self._hostname())
                self._send(308, "", "text/plain", headers=[("Location", f"https://{host}/")])
            else:
                self._json(403, {"ok": False, "output": "HTTPS required"})
            return False
        return True

    # -- routes

    def do_GET(self):
        self._request_received()
        if not self._gate():
            return
        path = urlsplit(self.path).path
        if path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /\n", "text/plain")
        if path == "/healthz" and not self.public:
            return self._send(200, "ok\n", "text/plain")
        if path == "/":
            return self._page(INDEX_HTML if self.authed() else LOGIN_HTML)
        if path == "/api/accounts":
            if not self.authed():
                return self._json(401, {"error": "login required"})
            return self._json(200, snapshot())
        return self._json(404, {"error": "not found"})

    do_HEAD = do_GET

    def _read_post(self):
        """Same-origin JSON POSTs only. Returns the parsed body, or None after replying."""
        if not self._gate():
            self._request_received()
            return None
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc.lower() != (self.headers.get("Host") or "").lower():
            self._request_received()
            return self._json(403, {"ok": False, "output": "cross-origin request refused"})
        # Requiring JSON forces a CORS preflight for cross-site pages, which we never grant.
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            self._request_received()
            return self._json(415, {"ok": False, "output": "expected application/json"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= 4096:
                raise ValueError
            raw = self.rfile.read(length)
            self._request_received()
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise ValueError
            return body
        except (ValueError, OSError):
            self._request_received()
            return self._json(400, {"ok": False, "output": "bad request"})

    def do_POST(self):
        path = urlsplit(self.path).path
        routes = ("/api/login", "/api/logout", "/api/logout-all", "/api/use", "/api/auto", "/api/check",
                  "/api/codex/use", "/api/codex/auto")
        if path not in routes:
            self._request_received()
            return self._json(404, {"ok": False, "output": "not found"})
        body = self._read_post()
        if body is None:
            return
        if path == "/api/login":
            return self._login(body.get("password"))
        if path == "/api/logout":
            nonce = session_nonce(self._cookie("cas_session"))
            if nonce:
                SESSIONS.remove(nonce)
            return self._json(200, {"ok": True}, headers=[("Set-Cookie", self._set_cookie("cas_session", "", 0))])
        if not self.authed():
            return self._json(401, {"ok": False, "output": "login required"})
        if path == "/api/logout-all":
            SESSIONS.clear()
            DEVICES.clear()
            log(f"all sessions and remembered browsers signed out by {self.client_ip()}")
            return self._json(200, {"ok": True}, headers=[
                ("Set-Cookie", self._set_cookie("cas_session", "", 0)),
                ("Set-Cookie", self._set_cookie("cas_device", "", 0))])
        if not action_allowed():
            return self._json(429, {"ok": False, "output": "Slow down — try again in a moment."},
                              headers=[("Retry-After", "2")])
        if path == "/api/use":
            return self._use(body.get("name"))
        if path == "/api/codex/use":
            return self._codex_use(body.get("name"))
        if path in ("/api/auto", "/api/codex/auto"):
            enabled = body.get("enabled")
            if not isinstance(enabled, bool):
                return self._json(400, {"ok": False, "output": "enabled must be true/false"})
            what = "Codex auto-switch" if path == "/api/codex/auto" else "Auto-switch"
            with LOCK:
                if path == "/api/codex/auto":
                    AUTO.codex_enabled = enabled
                else:
                    AUTO.enabled = enabled
                AUTO.event(f"{what} turned {'on' if enabled else 'off'}.")
                AUTO.save()
            if enabled:
                AUTO.tick(force=True)
            return self._json(200, {"ok": True, "output": f"{what} is {'on' if enabled else 'off'}.",
                                    **snapshot()})
        AUTO.tick(force=True)  # /api/check
        return self._json(200, {"ok": True, "output": "Usage refreshed.", **snapshot()})

    def _login(self, password):
        device = device_id(self._cookie("cas_device"))
        key = rate_bucket(self.public, self.forwarded_ip(), device)
        count_global = self.public and not device
        wait = LIMITER.retry_after(key, count_global)
        if wait:
            return self._json(429, {"ok": False, "output": f"Too many attempts. Try again in {wait // 60 + 1} min."},
                              headers=[("Retry-After", str(wait))])
        if not LOGIN_SLOTS.acquire(blocking=False):
            return self._json(429, {"ok": False, "output": "Busy, try again."}, headers=[("Retry-After", "5")])
        try:
            if password_ok(password):
                LIMITER.reset(key)
                log(f"login ok from {self.client_ip()}{' (internet)' if self.public else ''}")
                cookies = [("Set-Cookie", self._set_cookie("cas_session", make_session(), int(SESSION_DAYS * 86400)))]
                if not device:  # remember this browser so lockouts aimed at others never hit it
                    cookies.append(("Set-Cookie", self._set_cookie("cas_device", make_device(), DEVICE_DAYS * 86400)))
                return self._json(200, {"ok": True}, headers=cookies)
            LIMITER.fail(key, count_global)
            log(f"login FAILED from {self.client_ip()}{' (internet)' if self.public else ''}")
            time.sleep(FAIL_DELAY)  # slow down guessing
            return self._json(401, {"ok": False, "output": "Wrong password."})
        finally:
            LOGIN_SLOTS.release()

    def _codex_use(self, name):
        if not isinstance(name, str) or not NAME_RE.match(name):
            return self._json(400, {"ok": False, "output": "invalid account name"})
        with LOCK:
            before = list_codex_accounts()
            if before["error"]:
                return self._json(500, {"ok": False, "output": before["error"], **AUTO.decorate(list_accounts(), before)})
            names = [a["name"] for a in before["accounts"]]
            if name not in names:
                return self._json(400, {"ok": False, "output": f"no saved Codex account '{name}'",
                                        **AUTO.decorate(list_accounts(), before)})
            active = next((a["name"] for a in before["accounts"] if a["active"]), None)
            code, out, err = run("use", name, cli=CODEX_CLI)
            if code == 0 and active != name:
                AUTO.codex_last_switch_at = time.time()
                AUTO.event(f"Codex switched {active or '(unsaved login)'} → {name} by hand.", "switch")
                AUTO.codex_manual_switch(name, names)
            st = AUTO.decorate(list_accounts())
        self.log_message('codex switch to "%s": exit %d', name, code)
        output = "\n".join(s for s in (out.strip(), err.strip()) if s) or f"exit code {code}"
        return self._json(200 if code == 0 else 500, {"ok": code == 0, "output": output, **st})

    def _use(self, name):
        if not isinstance(name, str) or not NAME_RE.match(name):
            return self._json(400, {"ok": False, "output": "invalid account name"})
        with LOCK:
            before = list_accounts()
            if before["error"]:
                return self._json(500, {"ok": False, "output": before["error"], **AUTO.decorate(before)})
            names = [a["name"] for a in before["accounts"]]
            if name not in names:
                return self._json(400, {"ok": False, "output": f"no saved account '{name}'",
                                        **AUTO.decorate(before)})
            active = next((a["name"] for a in before["accounts"] if a["active"]), None)
            problem = AUTO.identity_problem(active, names) if active and active != name else None
            if problem:
                return self._json(409, {"ok": False, "output": problem, **AUTO.decorate(before)})
            code, out, err = run("use", name)
            if code == 0 and active != name:
                AUTO.event(f"Switched {active} → {name} manually.", "switch")
                AUTO.manual_switch(name, names)
            st = AUTO.decorate(list_accounts())
        self.log_message('switch to "%s": exit %d', name, code)
        output = "\n".join(s for s in (out.strip(), err.strip()) if s) or f"exit code {code}"
        return self._json(200 if code == 0 else 500, {"ok": code == 0, "output": output, **st})


def check_config():
    problems = list(ENV_PROBLEMS)
    if MASTER_PASSWORD.lower() in PLACEHOLDERS or len(MASTER_PASSWORD) < MIN_PASSWORD_LEN:
        problems.append(f"MASTER_PASSWORD is missing, a placeholder, or shorter than {MIN_PASSWORD_LEN} characters")
    if SESSION_SECRET.lower() in PLACEHOLDERS or len(SESSION_SECRET) < 32:
        problems.append("SESSION_SECRET is missing, a placeholder, or shorter than 32 characters")
    if BIND not in LOOPBACK_NAMES:
        problems.append(f"BIND={BIND}: only loopback is allowed; put a TLS reverse proxy on this machine in front")
    if bool(PUBLIC_PORT) != bool(PUBLIC_HOSTS):
        problems.append("set PUBLIC_PORT and ALLOWED_HOSTS together (the proxy listener and the domain it serves)")
    if PUBLIC_PORT and PUBLIC_PORT == PORT:
        problems.append("PUBLIC_PORT must differ from PORT")
    if PUBLIC_HOSTS & LOOPBACK_NAMES:
        problems.append("ALLOWED_HOSTS must only list your domain(s), not localhost names")
    return problems


def main():
    problems = check_config()
    if problems:
        for p in problems:
            log("config error: " + p)
        log("Fix .env (see .env.example). Refusing to start.")
        sys.exit(2)
    if "TRUST_PROXY" in os.environ:
        log("note: TRUST_PROXY is no longer used; point the proxy at PUBLIC_PORT instead")
    for d in {STATE_FILE.parent, SESSIONS_FILE.parent, DEVICES_FILE.parent}:
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(d, 0o700)
    local = Server((BIND, PORT), Handler)
    if PUBLIC_PORT:
        public = Server((BIND, PUBLIC_PORT), Handler, public=True)
        threading.Thread(target=public.serve_forever, name="public", daemon=True).start()
    threading.Thread(target=AUTO.loop, name="auto-switch", daemon=True).start()
    log(f"account-toggler: local http://{BIND}:{PORT}/"
        + (f"; public listener {BIND}:{PUBLIC_PORT} for {', '.join(sorted(PUBLIC_HOSTS))}" if PUBLIC_PORT else "")
        + f"; auto-switch {'on' if AUTO.enabled else 'off'} at {THRESHOLD:g}%, "
        + f"order {','.join(PRIORITY) or '(list order)'}; "
        + f"codex auto-switch {'on' if AUTO.codex_enabled else 'off'}, order {','.join(CODEX_PRIORITY) or '(list order)'}")
    try:
        local.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
