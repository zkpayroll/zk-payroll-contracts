#!/usr/bin/env python3
"""Check Soroban contract WASM artifacts against documented size thresholds."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "scripts" / "wasm-size-thresholds.json"
WASM_DIR = ROOT / "target" / "wasm32-unknown-unknown" / "release"


def main() -> int:
    config = json.loads(CONFIG.read_text())
    max_bytes = int(config["max_bytes"])
    warning_growth = float(config["warning_growth_percent"])
    failure_growth = float(config["failure_growth_percent"])
    artifacts = config["artifacts"]

    failures: list[str] = []
    warnings: list[str] = []
    rows: list[str] = [
        "| Artifact | Size | Baseline | Growth | Status |",
        "|----------|------|----------|--------|--------|",
    ]

    for artifact, baseline in sorted(artifacts.items()):
        path = WASM_DIR / artifact
        if not path.exists():
            failures.append(f"missing artifact: {path.relative_to(ROOT)}")
            rows.append(f"| `{artifact}` | missing | {baseline} | n/a | fail |")
            continue

        size = path.stat().st_size
        growth = ((size - baseline) / baseline) * 100 if baseline else 0.0
        status = "pass"

        if size > max_bytes:
            status = "fail"
            failures.append(f"{artifact} is {size} bytes, above {max_bytes} bytes")
        elif growth >= failure_growth:
            status = "fail"
            failures.append(
                f"{artifact} grew {growth:.2f}% from baseline ({baseline} -> {size})"
            )
        elif growth >= warning_growth:
            status = "warn"
            warnings.append(
                f"{artifact} grew {growth:.2f}% from baseline ({baseline} -> {size})"
            )

        rows.append(f"| `{artifact}` | {size} | {baseline} | {growth:.2f}% | {status} |")

    report = "\n".join(rows)
    print(report)

    github_step_summary = Path.cwd() / "GITHUB_STEP_SUMMARY"
    summary_path = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if summary_path:
        summary_path.write_text(report + "\n")

    if warnings:
        print("\nWarnings:")
        for warning in warnings:
            print(f"- {warning}")
    if failures:
        print("\nFailures:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
