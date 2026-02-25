#!/usr/bin/env bash
# setup-labels.sh — Create or update GitHub issue labels for zk-payroll-contracts.
#
# Usage:
#   gh auth login          # authenticate once
#   bash .github/scripts/setup-labels.sh
#
# Requires: GitHub CLI (gh) >= 2.x installed and authenticated.
# The script is idempotent: existing labels are updated, new ones are created.

set -euo pipefail

REPO="zkpayroll/zk-payroll-contracts"

# ── Helper ────────────────────────────────────────────────────────────────────

upsert_label() {
  local name="$1"
  local color="$2"   # hex without '#'
  local description="$3"

  if gh label list --repo "$REPO" --json name --jq '.[].name' | grep -qx "$name"; then
    echo "  Updating label: $name"
    gh label edit "$name" \
      --repo "$REPO" \
      --color "$color" \
      --description "$description"
  else
    echo "  Creating label: $name"
    gh label create "$name" \
      --repo "$REPO" \
      --color "$color" \
      --description "$description"
  fi
}

# ── Domain labels ─────────────────────────────────────────────────────────────

echo "Setting up domain labels..."

upsert_label "zk-circuits"     "7057ff" "Changes to Circom circuits or ZK proof system"
upsert_label "smart-contracts" "0075ca" "Changes to Soroban/Rust smart contracts"
upsert_label "state-rent"      "e4e669" "Issues affecting Stellar state rent or storage layout"
upsert_label "audit-module"    "d93f0b" "Selective disclosure / compliance audit module"
upsert_label "stellar-wave"    "0e8a16" "Eligible for Stellar Wave Program rewards"

# ── Workflow labels ───────────────────────────────────────────────────────────

echo "Setting up workflow labels..."

upsert_label "good first issue" "7057ff" "Good for newcomers — 100 points"
upsert_label "medium"           "fbca04" "Standard complexity — 150 points"
upsert_label "high"             "e11d48" "Complex implementation — 200 points"
upsert_label "bug"              "d73a4a" "Something isn't working"
upsert_label "enhancement"      "a2eeef" "New feature or improvement"
upsert_label "documentation"    "0075ca" "Improvements or additions to documentation"
upsert_label "security"         "b60205" "Security-sensitive change — requires careful review"
upsert_label "triage"           "ededed" "Needs initial review and categorisation"
upsert_label "wontfix"          "ffffff" "This will not be worked on"
upsert_label "duplicate"        "cfd3d7" "This issue or PR already exists"

echo ""
echo "Label setup complete for $REPO."
