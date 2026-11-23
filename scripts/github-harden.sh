#!/usr/bin/env bash
# Apply GitHub-side protections to the published repo. Run after creating it, and again
# every ~5 months (the interaction limit expires after 6):
#   scripts/github-harden.sh OWNER/REPO
# Needs the gh CLI logged in as the repo owner. Safe to re-run. Ends with a verification.
set -uo pipefail
R=${1:?usage: scripts/github-harden.sh OWNER/REPO}
fails=0
step() {
  local msg=$1; shift
  local err
  if err=$("$@" 2>&1 >/dev/null); then echo "  ✓ $msg"; else echo "  ✗ $msg: ${err:0:200}" >&2; fails=$((fails+1)); fi
}
feature() {  # one security_and_analysis feature per call, so one unavailable feature can't block the rest
  step "$1" gh api -X PATCH "repos/$R" --input - <<<"{\"security_and_analysis\": {\"$2\": {\"status\": \"enabled\"}}}"
}

echo "Hardening $R"
feature "secret scanning"                   secret_scanning
feature "secret scanning push protection"   secret_scanning_push_protection
feature "secret scanning: non-provider patterns" secret_scanning_non_provider_patterns
feature "secret scanning: validity checks"  secret_scanning_validity_checks
step "Dependabot alerts" gh api -X PUT "repos/$R/vulnerability-alerts"
step "Dependabot security updates" gh api -X PUT "repos/$R/automated-security-fixes"
step "private vulnerability reporting" gh api -X PUT "repos/$R/private-vulnerability-reporting"
step "issues, discussions, wiki, projects off (no public input for bots or agents)" \
  gh api -X PATCH "repos/$R" -F has_issues=false -F has_discussions=false -F has_wiki=false -F has_projects=false
step "workflow token read-only, cannot approve PRs" gh api -X PUT "repos/$R/actions/permissions/workflow" \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
step "only GitHub-owned actions, pinned to full SHAs" gh api -X PUT "repos/$R/actions/permissions" \
  -F enabled=true -f allowed_actions=selected -F sha_pinning_required=true
step "allow-list: GitHub-owned only" gh api -X PUT "repos/$R/actions/permissions/selected-actions" --input - <<'JSON'
{"github_owned_allowed": true, "verified_allowed": false, "patterns_allowed": []}
JSON
step "workflows from outside contributors need approval" gh api -X PUT \
  "repos/$R/actions/permissions/fork-pr-contributor-approval" -f approval_policy=all_external_contributors
step "only collaborators may open PRs/comment (6 months; re-run to renew)" gh api -X PUT \
  "repos/$R/interaction-limits" -f limit=collaborators_only -f expiry=six_months

BR=$(gh api "repos/$R" --jq .default_branch)
RULESET='{"name": "protect-default-branch", "target": "branch", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
 "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}]}'
RID=$(gh api "repos/$R/rulesets" --jq '.[] | select(.name=="protect-default-branch") | .id' 2>/dev/null)
if [ -n "$RID" ]; then
  step "ruleset: no force-push/deletion of $BR (updated)" gh api -X PUT "repos/$R/rulesets/$RID" --input - <<<"$RULESET"
else
  step "ruleset: no force-push/deletion of $BR" gh api -X POST "repos/$R/rulesets" --input - <<<"$RULESET"
fi

echo; echo "Verification:"
gh api "repos/$R" --jq '"  visibility=\(.visibility) issues=\(.has_issues) wiki=\(.has_wiki)",
  (.security_and_analysis // {} | to_entries[] | "  \(.key)=\(.value.status)")'
gh api "repos/$R/actions/permissions" --jq '"  actions: allowed=\(.allowed_actions) sha_pinning_required=\(.sha_pinning_required)"'
gh api "repos/$R/actions/permissions/workflow" --jq '"  workflow token=\(.default_workflow_permissions)"'
gh api "repos/$R/interaction-limits" --jq '"  interaction limit=\(.limit // "none") until \(.expires_at // "-")"' 2>/dev/null
echo
echo "Also, once per account (no API for these): Settings → Emails → 'Keep my email address private'"
echo "and 'Block command line pushes that expose my email'."
echo "Optional: gh secret set LEAKCHECK_DENYLIST -R $R < .leakcheck-denylist"
exit $(( fails > 0 ))
