"""Severity levels shared by Sigma rule ``level`` fields and validation findings."""

from __future__ import annotations

from enum import Enum
from typing import Final

from sigma_detection_engineering_lab.errors import SdelError


class UnknownSeverityError(SdelError):
    """The supplied value is not a recognised severity level."""


class Severity(str, Enum):
    """Ordered severity scale, matching the Sigma ``level`` vocabulary."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __str__(self) -> str:
        return self.value

    @property
    def rank(self) -> int:
        """Return a numeric rank where a larger number is more severe."""
        return _RANK[self]

    def at_least(self, other: Severity) -> bool:
        """Return whether this severity is as severe as ``other`` or more so."""
        return self.rank >= other.rank


_RANK: Final[dict[Severity, int]] = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_ALIASES: Final[dict[str, Severity]] = {
    "info": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

ORDERED: Final[tuple[Severity, ...]] = (
    Severity.INFORMATIONAL,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)

SARIF_LEVELS: Final[dict[Severity, str]] = {
    Severity.INFORMATIONAL: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}
"""SARIF ``level`` for each severity. SARIF offers only note/warning/error."""

HTML_COLORS: Final[dict[Severity, str]] = {
    Severity.INFORMATIONAL: "#5a6b7c",
    Severity.LOW: "#2f7d4f",
    Severity.MEDIUM: "#9a6b00",
    Severity.HIGH: "#b3480f",
    Severity.CRITICAL: "#a01b2b",
}


def parse_severity(value: object) -> Severity:
    """Coerce ``value`` to a :class:`Severity`.

    Raises:
        UnknownSeverityError: if the value is absent or unrecognised.
    """
    if isinstance(value, Severity):
        return value
    if not isinstance(value, str):
        raise UnknownSeverityError(f"severity must be a string, got {type(value).__name__}")
    normalised = value.strip().lower()
    try:
        return _ALIASES[normalised]
    except KeyError as exc:
        known = ", ".join(s.value for s in ORDERED)
        raise UnknownSeverityError(f"unknown severity {value!r}; expected one of: {known}") from exc


def max_severity(*values: Severity) -> Severity:
    """Return the most severe of the supplied severities."""
    if not values:
        return Severity.INFORMATIONAL
    return max(values, key=lambda severity: severity.rank)


def to_sarif_level(severity: Severity) -> str:
    """Map a severity onto the SARIF ``level`` vocabulary."""
    return SARIF_LEVELS[severity]


__all__ = [
    "HTML_COLORS",
    "ORDERED",
    "SARIF_LEVELS",
    "Severity",
    "UnknownSeverityError",
    "max_severity",
    "parse_severity",
    "to_sarif_level",
]
