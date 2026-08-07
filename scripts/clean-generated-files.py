#!/usr/bin/env python3
"""Remove only known generated/ignored outputs. Requires --apply."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    "temp",
    "tmp",
    "reports",
    "results",
    "output",
    "coverage",
    "test-results",
    "dist",
    "build",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "htmlcov",
    ".coverage",
    "coverage.xml",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    planned: list[Path] = []
    for name in TARGETS:
        path = ROOT / name
        if path.exists():
            if path.is_symlink():
                print(f"REFUSE symlink: {path}")
                return 2
            planned.append(path)
    if not planned:
        print("Nothing to remove")
        return 0
    print("Planned removals:")
    for path in planned:
        print(" ", path)
    if not args.apply:
        print("Dry run only. Re-run with --apply to delete.")
        return 0
    for path in planned:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        print("removed", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
