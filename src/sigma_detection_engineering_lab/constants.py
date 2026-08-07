"""Shared literal constants, especially the mandatory disclosure banners.

The banner strings are contractual: reports, conversions, and console output
must reproduce them verbatim so that no artefact of this laboratory can be
mistaken for validated production detection content.
"""

from __future__ import annotations

from typing import Final

SYNTHETIC_DATA_BANNER: Final[str] = "SYNTHETIC DEMONSTRATION DATA"
"""Marks every artefact derived from generated telemetry."""

CONVERSION_DEMONSTRATION_BANNER: Final[str] = (
    "DEMONSTRATION CONVERSION \u2014 ENVIRONMENT-SPECIFIC VALIDATION REQUIRED"
)
"""Marks every backend query emitted by :mod:`~sigma_detection_engineering_lab.conversion`."""

SYNTHETIC_TESTING_BANNER: Final[str] = (
    "SYNTHETIC BEHAVIORAL TESTING \u2014 NOT A MEASUREMENT OF PRODUCTION DETECTION EFFICACY"
)
"""Marks behavioral test results, which exercise generated events only."""

COVERAGE_CAVEAT_BANNER: Final[str] = (
    "COVERAGE REFLECTS AUTHORED RULES AND SYNTHETIC TESTS ONLY \u2014 "
    "NOT ENVIRONMENTAL DETECTION COVERAGE"
)
"""Marks coverage reports, which count authored content rather than real visibility."""

NO_PRODUCTION_CLAIM: Final[str] = (
    "This artefact makes no claim of production readiness. Queries, mappings, and "
    "metrics require environment-specific validation before operational use."
)
"""Long-form disclaimer embedded in machine-readable and human-readable reports."""

NO_EFFICACY_METRICS_NOTE: Final[str] = (
    "Precision, recall, and false-positive rate are intentionally not reported: "
    "they cannot be derived from synthetic fixtures."
)

PROJECT_AUTHOR: Final[str] = "Salvatore Mazzaglia"
PROJECT_LICENSE: Final[str] = "MIT"
PROJECT_ROOT_MARKER: Final[str] = "pyproject.toml"

EVALUATOR_NAME: Final[str] = "sdel-lab-matcher-v1"
"""Identifier of the documented matcher subset, recorded in every test report."""

SCHEMA_VERSION: Final[str] = "1.0.0"

ALL_BANNERS: Final[tuple[str, ...]] = (
    SYNTHETIC_DATA_BANNER,
    CONVERSION_DEMONSTRATION_BANNER,
    SYNTHETIC_TESTING_BANNER,
    COVERAGE_CAVEAT_BANNER,
)

__all__ = [
    "ALL_BANNERS",
    "CONVERSION_DEMONSTRATION_BANNER",
    "COVERAGE_CAVEAT_BANNER",
    "EVALUATOR_NAME",
    "NO_EFFICACY_METRICS_NOTE",
    "NO_PRODUCTION_CLAIM",
    "PROJECT_AUTHOR",
    "PROJECT_LICENSE",
    "PROJECT_ROOT_MARKER",
    "SCHEMA_VERSION",
    "SYNTHETIC_DATA_BANNER",
    "SYNTHETIC_TESTING_BANNER",
]
