"""Sigma rule statuses and laboratory maturity levels.

Two distinct vocabularies are modelled here. :class:`SigmaStatus` is the upstream
Sigma specification field. :class:`Maturity` is a laboratory-local judgement
recorded in the sidecar, describing how much evidence backs a rule.

``stable`` is deliberately blocked in the main catalog: nothing validated only
against synthetic telemetry may present itself as production-proven.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum
from typing import Final

from sigma_detection_engineering_lab.errors import SdelError


class UnknownStatusError(SdelError):
    """The supplied value is not a Sigma specification status."""


class UnknownMaturityError(SdelError):
    """The supplied value is not a laboratory maturity level."""


class SigmaStatus(str, Enum):
    """Status values defined by the Sigma rules specification."""

    STABLE = "stable"
    TEST = "test"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"

    def __str__(self) -> str:
        return self.value


class Maturity(str, Enum):
    """Laboratory evidence level recorded in a rule sidecar."""

    DRAFT = "draft"
    EXPERIMENTAL = "experimental"
    TESTED_SYNTHETIC = "tested-synthetic"
    VALIDATED_LAB = "validated-lab"
    PRODUCTION_OBSERVED = "production-observed"
    DEPRECATED = "deprecated"

    def __str__(self) -> str:
        return self.value


MAIN_CATALOG_ALLOWED_STATUSES: Final[frozenset[SigmaStatus]] = frozenset(
    {SigmaStatus.EXPERIMENTAL, SigmaStatus.TEST}
)
"""Only these statuses may appear on a rule in the main catalog."""

MAIN_CATALOG_BLOCKED_STATUSES: Final[frozenset[SigmaStatus]] = frozenset({SigmaStatus.STABLE})
"""``stable`` asserts production validation this project cannot substantiate."""

RETIRED_STATUSES: Final[frozenset[SigmaStatus]] = frozenset(
    {SigmaStatus.DEPRECATED, SigmaStatus.UNSUPPORTED}
)
"""Permitted only outside the main catalog, in the retired-rule area."""

MAIN_CATALOG_ALLOWED_MATURITY: Final[frozenset[Maturity]] = frozenset(
    {Maturity.EXPERIMENTAL, Maturity.TESTED_SYNTHETIC}
)
"""Synthetic evidence supports no stronger claim than ``tested-synthetic``."""

EVIDENCE_UNSUPPORTED_MATURITY: Final[frozenset[Maturity]] = frozenset(
    {Maturity.VALIDATED_LAB, Maturity.PRODUCTION_OBSERVED}
)
"""Maturity levels that would require real telemetry the laboratory never handles."""

_MATURITY_RANK: Final[dict[Maturity, int]] = {
    Maturity.DEPRECATED: -1,
    Maturity.DRAFT: 0,
    Maturity.EXPERIMENTAL: 1,
    Maturity.TESTED_SYNTHETIC: 2,
    Maturity.VALIDATED_LAB: 3,
    Maturity.PRODUCTION_OBSERVED: 4,
}


def parse_status(value: object) -> SigmaStatus:
    """Coerce ``value`` to a :class:`SigmaStatus`.

    Raises:
        UnknownStatusError: if the value is absent or not a specification status.
    """
    if isinstance(value, SigmaStatus):
        return value
    if not isinstance(value, str):
        raise UnknownStatusError(f"status must be a string, got {type(value).__name__}")
    normalised = value.strip().lower()
    try:
        return SigmaStatus(normalised)
    except ValueError as exc:
        known = ", ".join(sorted(s.value for s in SigmaStatus))
        raise UnknownStatusError(
            f"unknown Sigma status {value!r}; expected one of: {known}"
        ) from exc


def parse_maturity(value: object) -> Maturity:
    """Coerce ``value`` to a :class:`Maturity`.

    Raises:
        UnknownMaturityError: if the value is absent or not a laboratory maturity.
    """
    if isinstance(value, Maturity):
        return value
    if not isinstance(value, str):
        raise UnknownMaturityError(f"maturity must be a string, got {type(value).__name__}")
    normalised = value.strip().lower()
    try:
        return Maturity(normalised)
    except ValueError as exc:
        known = ", ".join(sorted(m.value for m in Maturity))
        raise UnknownMaturityError(f"unknown maturity {value!r}; expected one of: {known}") from exc


def is_status_allowed_in_main_catalog(status: SigmaStatus) -> bool:
    """Return whether ``status`` may appear on a main-catalog rule."""
    return status in MAIN_CATALOG_ALLOWED_STATUSES


def is_status_blocked(status: SigmaStatus) -> bool:
    """Return whether ``status`` is hard-blocked everywhere in the main catalog."""
    return status in MAIN_CATALOG_BLOCKED_STATUSES


def is_maturity_allowed_in_main_catalog(maturity: Maturity) -> bool:
    """Return whether ``maturity`` is supported by synthetic-only evidence."""
    return maturity in MAIN_CATALOG_ALLOWED_MATURITY


def maturity_rank(maturity: Maturity) -> int:
    """Return an ordering rank so maturities can be compared and sorted."""
    return _MATURITY_RANK[maturity]


def parse_status_set(values: Iterable[object]) -> frozenset[SigmaStatus]:
    """Parse an iterable of status values, typically from configuration."""
    return frozenset(parse_status(value) for value in values)


def parse_maturity_set(values: Iterable[object]) -> frozenset[Maturity]:
    """Parse an iterable of maturity values, typically from configuration."""
    return frozenset(parse_maturity(value) for value in values)


__all__ = [
    "EVIDENCE_UNSUPPORTED_MATURITY",
    "MAIN_CATALOG_ALLOWED_MATURITY",
    "MAIN_CATALOG_ALLOWED_STATUSES",
    "MAIN_CATALOG_BLOCKED_STATUSES",
    "RETIRED_STATUSES",
    "Maturity",
    "SigmaStatus",
    "UnknownMaturityError",
    "UnknownStatusError",
    "is_maturity_allowed_in_main_catalog",
    "is_status_allowed_in_main_catalog",
    "is_status_blocked",
    "maturity_rank",
    "parse_maturity",
    "parse_maturity_set",
    "parse_status",
    "parse_status_set",
]
