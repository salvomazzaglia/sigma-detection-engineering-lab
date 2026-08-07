"""Offline Sigma detection-engineering laboratory.

This package authors, validates, tests, documents, maps, compares, and converts
original Sigma detection rules entirely offline. It never connects to a SIEM,
never reads host logs, and never evaluates untrusted code.
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "Salvatore Mazzaglia"
__license__ = "MIT"

PACKAGE_NAME = "sigma_detection_engineering_lab"
DISTRIBUTION_NAME = "sigma-detection-engineering-lab"
CLI_NAME = "sigma-detection-lab"

__all__ = [
    "CLI_NAME",
    "DISTRIBUTION_NAME",
    "PACKAGE_NAME",
    "__author__",
    "__license__",
    "__version__",
]
