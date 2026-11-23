# Security policy

This is a small personal tool. If you find a vulnerability, please report it
privately through GitHub's **Report a vulnerability** button (Security tab →
Advisories). Do not open a public issue for security problems.

## Design summary

- Every page and API call needs the master password (20+ characters). Wrong
  passwords are rate-limited per IP (5 per 15 min) and globally for internet traffic
  (20 per hour). Previously signed-in browsers and the SSH tunnel are exempt from the
  global lock. Every failure is logged with the client IP.
- Sessions are HMAC-signed, server-side revocable, HttpOnly, `SameSite=Strict`
  cookies. From the internet only `__Host-`/`Secure` cookies over HTTPS are accepted,
  and plain-HTTP logins are refused.
- POST endpoints accept same-origin JSON only, and requests for unknown `Host`
  names are refused. Pages use a nonce-based Content-Security-Policy and refuse to be
  framed.
- The server binds to 127.0.0.1 and is meant to sit behind a TLS reverse proxy.
- No secrets live in this repository. Configuration is in a git-ignored `.env`
  (see `.env.example`). Pre-commit/pre-push hooks (installed as reviewed copies, not
  run from the tree) and CI (gitleaks, TruffleHog, a built-in history scanner,
  CodeQL) scan for leaks.
- Issues are disabled. Use private vulnerability reporting.
