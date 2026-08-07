#!/usr/bin/env python3
"""Local CI orchestrator for offline quality gates."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable


def run(label: str, args: list[str]) -> tuple[int, str]:
    print(f"\n=== {label} ===")
    print("+", " ".join(args))
    proc = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    if proc.stdout:
        print(proc.stdout)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)
    print(f"exit={proc.returncode}")
    return proc.returncode, proc.stdout + "\n" + proc.stderr


def main() -> int:
    failures = 0
    results: dict[str, int] = {}

    steps: list[tuple[str, list[str]]] = [
        ("ruff_lint", [PY, "-m", "ruff", "check", "src", "tests", "scripts"]),
        ("ruff_format", [PY, "-m", "ruff", "format", "--check", "src", "tests", "scripts"]),
        ("mypy", [PY, "-m", "mypy", "src"]),
        ("pytest", [PY, "-m", "pytest", "-q", "--tb=line"]),
        (
            "validate",
            [
                PY,
                "-m",
                "sigma_detection_engineering_lab",
                "validate",
                "--rules",
                "rules",
                "--metadata",
                "metadata/rules",
                "--strict",
            ],
        ),
        (
            "coverage",
            [
                PY,
                "-m",
                "sigma_detection_engineering_lab",
                "coverage",
                "--tests",
                "--json-out",
                "temp/ci-coverage.json",
            ],
        ),
        (
            "convert_splunk",
            [
                PY,
                "-m",
                "sigma_detection_engineering_lab",
                "convert",
                "--backend",
                "splunk",
                "--output",
                "temp/ci-splunk.json",
            ],
        ),
        (
            "convert_es",
            [
                PY,
                "-m",
                "sigma_detection_engineering_lab",
                "convert",
                "--backend",
                "elasticsearch-lucene",
                "--output",
                "temp/ci-es.json",
            ],
        ),
        ("upstream_catalog", [PY, "scripts/validate-upstream-catalog.py"]),
        ("build", [PY, "-m", "build"]),
    ]

    (ROOT / "temp").mkdir(exist_ok=True)
    for label, args in steps:
        code, _out = run(label, args)
        results[label] = code
        if code != 0:
            failures += 1

    # Summaries from catalog
    rule_files = list((ROOT / "rules").rglob("*.yml"))
    corr = [p for p in rule_files if "correlation" in p.as_posix()]
    standard = [p for p in rule_files if p not in corr]
    print("\n=== SUMMARY COUNTS ===")
    print("standard_rules", len(standard))
    print("correlation_rules", len(corr))
    print("total_rules", len(rule_files))
    print("metadata", len(list((ROOT / "metadata" / "rules").glob("*.json"))))
    print("positive_fixtures", len(list((ROOT / "fixtures").rglob("positive/*.jsonl"))))
    print("negative_fixtures", len(list((ROOT / "fixtures").rglob("negative/*.jsonl"))))
    print("step_results", json.dumps(results, indent=2))
    print("final_result", "PASS" if failures == 0 else "FAIL")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
