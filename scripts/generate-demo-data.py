#!/usr/bin/env python3
"""Regenerate deterministic synthetic catalog content (never inspects host logs)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "tools" / "generate_all_rules.py"


def main() -> int:
    if not GENERATOR.is_file():
        raise SystemExit(f"Missing generator: {GENERATOR}")
    print("Regenerating synthetic rules/metadata/fixtures via tools/generate_all_rules.py")
    print("This command never inspects host logs and never connects to a SIEM.")
    subprocess.run([sys.executable, str(GENERATOR)], cwd=ROOT, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
