# WASM Size Regression Thresholds

Contract WASM size is a release-blocking signal for Soroban deployments. This
project treats size growth as a regression when it makes deployment risk harder
to reason about, even if the artifact is still below the network maximum.

## Thresholds

| Threshold | Limit | CI behavior | Response |
|-----------|-------|-------------|----------|
| Baseline drift | +5% from the documented baseline | Warning in the workflow summary | Explain the increase in the PR and link the code path that caused it. |
| Review gate | +10% from the documented baseline | Workflow failure | Add an optimization plan or get maintainer approval before merging. |
| Deployment ceiling | 64 KiB per contract WASM | Workflow failure | Reduce the artifact size before release. |

The 64 KiB ceiling is intentionally documented as a project deployment guardrail
for production-like environments. If Soroban network policy changes, update this
page and the workflow in the same PR.

## Alert surfaces

Size alerts surface in three places:

1. The `WASM size regression alert` GitHub Actions job summary lists each
   artifact, its size, the configured baseline, and the percentage change.
2. Pull requests receive a failing required check when an artifact crosses the
   review gate or deployment ceiling.
3. Release operators should copy any warning or failure into the cutover or
   rollback thread so SDK and dashboard owners can assess downstream impact.

## Contributor expectations

Before opening a PR that changes contract code, run a release WASM build and
check sizes locally:

```bash
cargo build --target wasm32-unknown-unknown --release
python3 scripts/check-wasm-size.py
```

If size growth is expected, include the reason in the PR description. Useful
investigation steps include:

- Compare `target/wasm32-unknown-unknown/release/*.wasm` sizes before and after
  the change.
- Check for new dependencies or features in the contract `Cargo.toml` files.
- Look for duplicated serialization, validation, or test-only code that may have
  entered the contract crate.
- Re-run the build from a clean target directory before declaring a regression.

## Baseline maintenance

Baselines live in `scripts/wasm-size-thresholds.json`. Update a baseline only
when maintainers accept the new size after reviewing the reason for growth. A
baseline update PR must include the previous size, the new size, and the issue or
PR that justified the increase.
