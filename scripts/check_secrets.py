#!/usr/bin/env python3
"""Leak check: stop secrets and personal data from reaching this (public) repo.

  check_secrets.py --staged          pre-commit: the staged version of each file
  check_secrets.py --all             every tracked file in the working tree
  check_secrets.py --history RANGE   pre-push / CI: every added line and commit message
                                     in RANGE (e.g. HEAD, or old..new), every tag message,
                                     plus author, committer and tagger emails
  --require-local                    (hooks) fail if neither .env nor .leakcheck-denylist is
                                     found, so the personal checks can't silently switch off

Blocks: forbidden files (.env, keys, credential dumps, state), well-known token formats,
real values for secret-looking settings, email addresses outside an allowlist, every
secret value from the local .env, and every string in the local .leakcheck-denylist or
the LEAKCHECK_DENYLIST environment variable (newline-separated; set it from a CI secret).
Secret values and denylist strings are also searched for in binary and UTF-16 files.
A line containing "leakcheck:allow" skips only the pattern and email checks, never the
.env-value and denylist checks. Findings never print the matched text.

The hooks run an *installed copy* of this file (scripts/install-hooks.sh), so a change
to it in the repo has no effect until you have reviewed it and re-installed.
"""
import os
import re
import subprocess
import sys
from pathlib import Path


def git(*args, binary=False):
    out = subprocess.run(["git", *args], capture_output=True, check=True).stdout
    return out if binary else out.decode("utf-8", "replace")


ROOT = Path(git("rev-parse", "--show-toplevel").strip())
# In a linked worktree (T3 Code uses them) .env and the denylist live in the main checkout.
MAIN_ROOT = Path(git("rev-parse", "--path-format=absolute", "--git-common-dir").strip()).parent
LOCAL_DIRS = list(dict.fromkeys([ROOT, MAIN_ROOT]))

FORBIDDEN_FILE = re.compile(
    r"(^|/)(\.env(\..*)?|\.leakcheck-denylist|[^/]*\.(pem|key|p12|pfx|keystore)|"
    r"id_(rsa|dsa|ecdsa|ed25519)[^/]*|\.?credentials\.json|oauthAccount\.json|state\.json|"
    r"sessions\.json|devices\.json|\.netrc|"
    r"\.gitleaks\.toml|\.gitleaksignore|\.trufflehogignore)$")  # scanner configs could switch scanners off
ALLOWED_FILE = {".env.example"}
PATTERNS = [
    ("Anthropic key/token", r"sk-ant-[A-Za-z0-9_-]{8,}"),
    ("OAuth token in JSON", r"\"(accessToken|refreshToken|idToken)\"\s*:\s*\"[^\"]{8,}\""),
    ("GitHub token", r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}"),
    ("AWS access key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("Private key block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("JWT / tunnel token", r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}"),
    ("Bearer token", r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._~+/-]{20,}"),
    ("Secret setting with a real value",  # KEY=value in env/shell/config files (not code)
     r"^\s*(export\s+)?[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*[:=]\s*[\"']?"
     r"(?!change-me\b|changeme\b)[A-Za-z0-9_+/=.~:@!%^&*-]{6,}[\"']?\s*(#.*)?$"),
]
PATTERNS = [(name, re.compile(rx)) for name, rx in PATTERNS]
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
ALLOWED_EMAIL = re.compile(
    r"(?i)(@(example\.(com|org|net)|users\.noreply\.github\.com)$|^noreply@(anthropic|github)\.com$)")
SECRET_KEY_NAME = re.compile(r"(?i)(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)")


def _read_lines(path):
    try:
        return path.read_text().splitlines()
    except OSError:
        return []


def local_files_found():
    return any((d / name).is_file() for d in LOCAL_DIRS for name in (".env", ".leakcheck-denylist"))


def local_secret_values():
    """Values of secret-looking keys in the local .env: these must never be committed."""
    values = []
    for line in [l for d in LOCAL_DIRS for l in _read_lines(d / ".env")]:
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = (s.strip().strip("'\"") for s in line.split("=", 1))
            if SECRET_KEY_NAME.search(key) and len(value) >= 8 and value.lower() not in ("change-me", "changeme"):
                values.append(value)
    return values


def denylist():
    lines = [l for d in LOCAL_DIRS for l in _read_lines(d / ".leakcheck-denylist")]
    lines += os.environ.get("LEAKCHECK_DENYLIST", "").splitlines()
    return [l.strip() for l in lines if len(l.strip()) >= 3 and not l.lstrip().startswith("#")]


def needles():
    """(label, [byte encodings]) for every literal that must never appear anywhere."""
    out = []
    for label, items, fold in (("a secret value from your local .env", local_secret_values(), False),
                               ("a string from the denylist", denylist(), True)):
        for item in items:
            forms = {item, item.lower()} if fold else {item}
            encs = set()
            for f in forms:
                for enc in ("utf-8", "utf-16-le", "utf-16-be"):
                    encs.add(f.encode(enc))
            out.append((label, fold, sorted(encs)))
    return out


def scan_bytes(where, data, needle_list):
    findings = []
    low = data.lower()
    for label, fold, encs in needle_list:
        hay = low if fold else data
        if any(e in hay for e in encs):
            findings.append(f"{where}: contains {label}")
    return findings


def scan_text(where, text):
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if "leakcheck:allow" in line:
            continue
        for name, rx in PATTERNS:
            if rx.search(line):
                findings.append(f"{where}:{lineno}: {name}")
        for m in EMAIL.finditer(line):
            if not ALLOWED_EMAIL.search(m.group(0)):
                findings.append(f"{where}:{lineno}: email address (use a placeholder like you@example.com)")
    return findings


def scan_files(staged):
    if staged:
        names = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split("\0")
        read = lambda p: git("show", f":{p}", binary=True)  # the staged version
    else:
        names = git("ls-files", "-z").split("\0")
        read = lambda p: (ROOT / p).read_bytes()
    needle_list, findings = needles(), []
    for path in filter(None, names):
        if FORBIDDEN_FILE.search(path) and path not in ALLOWED_FILE:
            findings.append(f"{path}: this file must never be committed")
            continue
        try:
            data = read(path)
        except (OSError, subprocess.CalledProcessError):
            continue
        findings += scan_bytes(path, data, needle_list)
        if b"\0" not in data[:8192]:
            findings += scan_text(path, data.decode("utf-8", "replace"))
    return findings


def scan_history(rev_range):
    findings, needle_list = [], needles()
    # identities that become public
    for email in sorted(set(git("log", "--format=%ae%n%ce", rev_range).split())):
        if not ALLOWED_EMAIL.search(email):
            findings.append(f"commit author/committer email '{_mask(email)}' would be published; set "
                            "git config user.email <id>+<user>@users.noreply.github.com and rewrite these commits")
    # commit messages, scanned on their own so no line is mistaken for diff context
    for entry in git("log", "--format=%h%x01%B%x00", rev_range).split("\0"):
        if "\x01" in entry:
            commit, msg = entry.strip("\n").split("\x01", 1)
            findings += scan_text(f"commit {commit} message", msg)
            findings += scan_bytes(f"commit {commit} message", msg.encode(), needle_list)
    # every added line (binary content too, via --text)
    log = git("log", "-p", "--text", "--no-ext-diff", "--no-color", "--format=%x00%h", rev_range, binary=True)
    findings += scan_bytes(f"history {rev_range}", log, needle_list)
    commit = "?"
    for line in log.decode("utf-8", "replace").splitlines():
        if line.startswith("\0"):
            commit = line[1:]
        elif line.startswith("+") and not line.startswith("+++"):
            findings += [f.replace(":1:", ":", 1) for f in scan_text(f"commit {commit}", line[1:])]
    # annotated tags: tagger and message
    for ref in git("for-each-ref", "refs/tags", "--format=%(objecttype) %(refname)").splitlines():
        kind, _, name = ref.partition(" ")
        if kind != "tag":
            continue
        obj = git("cat-file", "tag", name)
        tagger = re.search(r"^tagger .*<([^>]*)>", obj, re.M)
        if tagger and not ALLOWED_EMAIL.search(tagger.group(1)):
            findings.append(f"tag {name}: tagger email '{_mask(tagger.group(1))}' would be published")
        message = obj.split("\n\n", 1)[1] if "\n\n" in obj else ""
        findings += scan_text(f"tag {name} message", message)
        findings += scan_bytes(f"tag {name}", obj.encode(), needle_list)
    return sorted(set(findings))


def _mask(email):
    user, _, domain = email.partition("@")
    return f"{user[:1]}***@{domain}"


def main(argv):
    require_local = "--require-local" in argv
    argv = [a for a in argv if a != "--require-local"]
    if require_local and not local_files_found():
        print("leak check FAILED: no .env or .leakcheck-denylist found in "
              + " or ".join(str(d) for d in LOCAL_DIRS)
              + ", so your personal values can't be checked. Create .leakcheck-denylist.", file=sys.stderr)
        return 1
    if argv[:1] == ["--history"] and len(argv) == 2:
        findings = scan_history(argv[1])
    elif argv in (["--staged"], ["--all"]):
        findings = scan_files(staged=argv == ["--staged"])
    else:
        print(__doc__)
        return 2
    if findings:
        print("leak check FAILED — nothing was committed/pushed:", file=sys.stderr)
        for f in findings:
            print("  " + f, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
