"""Module entry point so ``python -m sigma_detection_engineering_lab`` works."""

from __future__ import annotations

import sys

from sigma_detection_engineering_lab.cli import main

if __name__ == "__main__":
    sys.exit(main())
