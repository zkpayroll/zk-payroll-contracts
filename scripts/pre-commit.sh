#!/usr/bin/env bash
#
# scripts/pre-commit.sh — ZK Payroll Contracts pre-commit hook
#
# Prevents commits of:
#   1. Rust code that fails `cargo fmt --check`
#   2. Circom circuits that fail compilation
#
# Both checks run only when relevant files are staged, so unrelated commits
# are not slowed down.  Missing tools (circom) produce warnings and skip the
# check gracefully — a clean clone without the full toolchain never blocks a
# commit that does not touch circuits.
#
# Installation (one-time, run from the repository root):
#   cp scripts/pre-commit.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Prerequisites:
#   - Rust / cargo   https://rustup.rs/
#   - circom 2.1+    https://docs.circom.io/getting-started/installation/
#   - Node.js 18+    https://nodejs.org/  (required by circom --wasm output)

set -euo pipefail

# Accumulate failures so the developer sees all problems in one pass.
PASS=true

# ── Helpers ──────────────────────────────────────────────────────────────────

log()  { echo "[pre-commit] $*"; }
ok()   { echo "[pre-commit] OK: $*"; }
fail() { echo "[pre-commit] FAIL: $*" >&2; PASS=false; }
warn() { echo "[pre-commit] WARN: $*" >&2; }

# ── 1. Rust formatting check ─────────────────────────────────────────────────
#
# Collects staged Rust source files and checks the whole workspace with
# `cargo fmt -- --check`.  We check the workspace (not individual files)
# because a formatter pass on one file can affect imports in another.

STAGED_RS=$(git diff --cached --name-only --diff-filter=ACMR 2>/dev/null \
    | grep '\.rs$' || true)

if [ -n "$STAGED_RS" ]; then
    log "Staged Rust files detected — running cargo fmt --check ..."

    if cargo fmt -- --check 2>&1; then
        ok "Rust formatting"
    else
        echo "" >&2
        echo "  One or more Rust files are not formatted." >&2
        echo "  Run the following command, then re-stage your changes:" >&2
        echo "    cargo fmt" >&2
        fail "Rust formatting check"
    fi
fi

# ── 2. Circom compilation check ──────────────────────────────────────────────
#
# When any .circom file is staged, all circuits under circuits/ are compiled
# together (circuits may import each other via `include` directives, so a
# partial check is unreliable).
#
# Compilation flags mirror CI:
#   --r1cs   generate the rank-1 constraint system
#   --wasm   generate the WebAssembly witness calculator
#   --sym    generate a symbols file (for debugging)
#   --c      generate the C witness calculator
#   --O0     disable optimisation (fast compile, suitable for CI / hooks)
#
# Output goes to a temporary directory that is removed on exit, ensuring that
# compiled artefacts are never accidentally staged.

STAGED_CIRCOM=$(git diff --cached --name-only --diff-filter=ACMR 2>/dev/null \
    | grep '\.circom$' || true)

if [ -n "$STAGED_CIRCOM" ]; then
    log "Staged Circom files detected — checking circuit compilation ..."

    if ! command -v circom &>/dev/null; then
        warn "circom not found — skipping circuit compilation check."
        warn "Install circom: https://docs.circom.io/getting-started/installation/"
    else
        # Verify that circuits/ contains at least one .circom file before
        # expanding the glob (avoids a cryptic circom error on empty dirs).
        shopt -s nullglob
        CIRCOM_FILES=(circuits/*.circom)
        shopt -u nullglob

        if [ ${#CIRCOM_FILES[@]} -eq 0 ]; then
            warn "No .circom files found in circuits/ — skipping."
        else
            BUILD_TMP=$(mktemp -d)
            # Guarantee cleanup regardless of exit path.
            # shellcheck disable=SC2064
            trap 'rm -rf "$BUILD_TMP"' EXIT

            if circom circuits/*.circom \
                    --r1cs --wasm --sym --c \
                    -o "$BUILD_TMP" \
                    --O0 2>&1; then
                ok "Circom compilation"
            else
                echo "" >&2
                echo "  Circom compilation failed." >&2
                echo "  Fix the errors above before committing." >&2
                fail "Circom compilation check"
            fi
        fi
    fi
fi

# ── Result ───────────────────────────────────────────────────────────────────

echo ""
if [ "$PASS" = "false" ]; then
    log "Commit rejected — fix the errors above and try again."
    exit 1
fi

log "All checks passed."
exit 0
