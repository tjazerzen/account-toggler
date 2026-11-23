#!/bin/sh
# Install the leak-check hooks by COPYING them (plus a pinned copy of check_secrets.py)
# into .git/hooks. Nothing in the working tree runs automatically, so a merged change
# to these files can't execute on your machine until you review it and re-run this.
set -e
cd "$(git rev-parse --show-toplevel)"
git config --unset core.hooksPath 2>/dev/null || true   # never run hooks from the tracked tree
HOOKS=$(git rev-parse --git-path hooks)
mkdir -p "$HOOKS"
install -m 0755 .githooks/pre-commit "$HOOKS/pre-commit"
install -m 0755 .githooks/pre-push "$HOOKS/pre-push"
install -m 0644 scripts/check_secrets.py "$HOOKS/check_secrets.py"
echo "Installed into $HOOKS:"
(cd "$HOOKS" && sha256sum pre-commit pre-push check_secrets.py)
