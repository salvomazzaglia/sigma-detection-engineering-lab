"""Offline rule conversion through the official pySigma backends.

Conversion runs entirely locally: a backend translates a Sigma rule into query
text, and nothing is deployed, uploaded, or executed. Every query produced here
carries :data:`~constants.CONVERSION_DEMONSTRATION_BANNER`, and every serialised
result carries ``production_ready: false``.

That framing is not decoration. A generated query has not been checked against a
real schema, field mapping, index configuration, or data model. It demonstrates
that the rule is convertible; it does not demonstrate that the query is correct
in any particular environment.

Three outcomes are distinguished and never merged. ``CONVERTED`` means a backend
produced a query. ``UNSUPPORTED`` means the backend refused a construct.
``BACKEND_UNAVAILABLE`` means the dependency is not installed. Only the first is
a success, so an environment missing pySigma cannot appear to pass.
"""

from __future__ import annotations

import importlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sigma_detection_engineering_lab.config import (
    BackendConfig,
    ConversionConfig,
    LabConfig,
    load_conversion_config,
)
from sigma_detection_engineering_lab.constants import (
    CONVERSION_DEMONSTRATION_BANNER,
    NO_PRODUCTION_CLAIM,
)
from sigma_detection_engineering_lab.models import (
    ConversionResult,
    ConversionStatus,
    Rule,
    utc_now_iso,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog

UNSUPPORTED_MARKERS: tuple[str, ...] = (
    "not supported",
    "unsupported",
    "cannot be converted",
    "no conversion",
    "notimplemented",
    "not implemented",
)
"""Substrings in a backend error that indicate refusal rather than a defect."""


@dataclass(frozen=True)
class BackendHandle:
    """A backend that has been resolved, or an explanation of why it was not."""

    key: str
    settings: BackendConfig
    backend: Any = None
    available: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "available": self.available,
            "error": self.error,
            "package": self.settings.package,
            "version": self.settings.version,
            "dialect": self.settings.dialect,
            "backend_class": self.settings.backend_class,
        }


def _import_known_backend(backend_class: str) -> Any:
    """Import one of the two pinned backends by its documented path.

    The imports are written out rather than resolved dynamically so the
    dependency on each backend is greppable and statically visible.
    """
    if backend_class == "sigma.backends.splunk.SplunkBackend":
        from sigma.backends.splunk import SplunkBackend

        return SplunkBackend
    if backend_class == "sigma.backends.elasticsearch.LuceneBackend":
        from sigma.backends.elasticsearch import LuceneBackend

        return LuceneBackend

    module_path, _, class_name = backend_class.rpartition(".")
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


def load_backend(settings: BackendConfig) -> BackendHandle:
    """Resolve and instantiate one backend.

    A missing dependency yields an unavailable handle rather than an exception,
    so the rest of the run continues and the gap is reported.
    """
    if not settings.enabled:
        return BackendHandle(
            key=settings.key,
            settings=settings,
            available=False,
            error="backend is disabled in config/conversion-backends.json",
        )

    try:
        backend_class = _import_known_backend(settings.backend_class)
    except ImportError as exc:
        return BackendHandle(
            key=settings.key,
            settings=settings,
            available=False,
            error=(
                f"{settings.package}=={settings.version} is not installed "
                f"({exc}); install the pinned dependencies to enable conversion"
            ),
        )
    except AttributeError as exc:
        return BackendHandle(
            key=settings.key,
            settings=settings,
            available=False,
            error=f"{settings.backend_class} is not present in the installed package: {exc}",
        )

    try:
        instance = backend_class()
    except Exception as exc:  # noqa: BLE001 - backend constructors vary widely
        return BackendHandle(
            key=settings.key,
            settings=settings,
            available=False,
            error=f"{settings.backend_class} could not be instantiated: {exc}",
        )

    return BackendHandle(key=settings.key, settings=settings, backend=instance, available=True)


def load_backends(conversion_config: ConversionConfig) -> tuple[BackendHandle, ...]:
    """Resolve every configured backend, enabled or not."""
    return tuple(load_backend(settings) for settings in conversion_config.backends)


def _looks_unsupported(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in UNSUPPORTED_MARKERS)


def _result(
    rule: Rule,
    handle: BackendHandle,
    status: ConversionStatus,
    *,
    queries: Sequence[str] = (),
    message: str = "",
) -> ConversionResult:
    return ConversionResult(
        catalog_id=rule.catalog_id,
        backend=handle.key,
        status=status,
        queries=tuple(queries),
        message=message,
        banner=handle.settings.demonstration_banner or CONVERSION_DEMONSTRATION_BANNER,
        backend_version=handle.settings.version or None,
        dialect=handle.settings.dialect or None,
    )


def convert_rule(
    rule: Rule,
    handle: BackendHandle,
    *,
    correlation_supported: bool = False,
) -> ConversionResult:
    """Convert one rule with one backend.

    Never raises: every failure mode becomes a classified result so the report
    shows exactly what happened for every rule and backend pair.
    """
    if not handle.available:
        return _result(
            rule,
            handle,
            ConversionStatus.BACKEND_UNAVAILABLE,
            message=handle.error or "backend is unavailable",
        )

    if not rule.raw_text:
        return _result(
            rule,
            handle,
            ConversionStatus.ERROR,
            message="rule source text is unavailable, so it cannot be converted",
        )

    try:
        from sigma.collection import SigmaCollection
    except ImportError as exc:
        return _result(
            rule,
            handle,
            ConversionStatus.BACKEND_UNAVAILABLE,
            message=f"pySigma is not installed ({exc})",
        )

    try:
        collection = SigmaCollection.from_yaml(rule.raw_text)
    except Exception as exc:  # noqa: BLE001 - pySigma raises a wide exception family
        return _result(
            rule,
            handle,
            ConversionStatus.ERROR,
            message=f"pySigma could not parse the rule: {type(exc).__name__}: {exc}",
        )

    try:
        converted = handle.backend.convert(collection)
    except Exception as exc:  # noqa: BLE001 - backends raise their own hierarchies
        message = f"{type(exc).__name__}: {exc}"
        if rule.is_correlation and not correlation_supported:
            return _result(
                rule,
                handle,
                ConversionStatus.UNSUPPORTED,
                message=(
                    "correlation conversion is not supported in v1.0 and the backend "
                    f"declined the rule: {message}"
                ),
            )
        status = (
            ConversionStatus.UNSUPPORTED if _looks_unsupported(message) else ConversionStatus.ERROR
        )
        return _result(rule, handle, status, message=message)

    queries = _normalise_queries(converted)
    if not queries:
        return _result(
            rule,
            handle,
            ConversionStatus.UNSUPPORTED,
            message="backend returned no query text for this rule",
        )

    return _result(
        rule,
        handle,
        ConversionStatus.CONVERTED,
        queries=queries,
        message=(
            f"converted by {handle.settings.package}=={handle.settings.version} "
            f"({handle.settings.dialect}); requires environment-specific validation"
        ),
    )


def _normalise_queries(converted: Any) -> tuple[str, ...]:
    """Flatten whatever shape a backend returned into a tuple of query strings."""
    if converted is None:
        return ()
    if isinstance(converted, str):
        return (converted,) if converted.strip() else ()
    if isinstance(converted, (list, tuple)):
        queries: list[str] = []
        for item in converted:
            queries.extend(_normalise_queries(item))
        return tuple(queries)
    text = str(converted).strip()
    return (text,) if text else ()


@dataclass(frozen=True)
class ConversionSet:
    """Every conversion attempted in one run."""

    results: tuple[ConversionResult, ...] = ()
    handles: tuple[BackendHandle, ...] = ()
    generated_at: str = ""
    banner: str = CONVERSION_DEMONSTRATION_BANNER
    correlation_supported: bool = False

    def for_rule(self, catalog_id: str) -> tuple[ConversionResult, ...]:
        return tuple(result for result in self.results if result.catalog_id == catalog_id)

    def for_backend(self, backend: str) -> tuple[ConversionResult, ...]:
        return tuple(result for result in self.results if result.backend == backend)

    def counts(self) -> dict[str, int]:
        """Count results per status. ``converted`` is the only success."""
        counts: dict[str, int] = {str(status): 0 for status in ConversionStatus}
        for result in self.results:
            counts[str(result.status)] += 1
        return counts

    @property
    def any_backend_available(self) -> bool:
        return any(handle.available for handle in self.handles)

    def to_dict(self) -> dict[str, Any]:
        return {
            "banner": self.banner,
            "disclaimer": NO_PRODUCTION_CLAIM,
            "production_ready": False,
            "generated_at": self.generated_at,
            "correlation_conversion_supported": self.correlation_supported,
            "backends": [handle.to_dict() for handle in self.handles],
            "counts": self.counts(),
            "results": [result.to_dict() for result in self.results],
        }


def convert_catalog(
    catalog: RuleCatalog,
    *,
    config: LabConfig,
    conversion_config: ConversionConfig | None = None,
    backend_keys: Sequence[str] | None = None,
    only: Sequence[str] | None = None,
) -> ConversionSet:
    """Convert the catalog with every enabled backend.

    Args:
        catalog: Rules to convert.
        config: Laboratory configuration, used to locate the backend config.
        conversion_config: Pre-loaded backend configuration, loaded if omitted.
        backend_keys: Restrict to these backend keys.
        only: Restrict to these catalog identifiers.
    """
    settings = conversion_config or load_conversion_config(config)
    wanted = set(backend_keys) if backend_keys else None
    selected = set(only) if only else None

    handles = tuple(
        handle for handle in load_backends(settings) if wanted is None or handle.key in wanted
    )

    results: list[ConversionResult] = []
    for rule in catalog:
        if selected is not None and rule.catalog_id not in selected:
            continue
        for handle in handles:
            if not handle.settings.enabled and not handle.available:
                continue
            results.append(
                convert_rule(
                    rule,
                    handle,
                    correlation_supported=settings.correlation_supported,
                )
            )

    return ConversionSet(
        results=tuple(results),
        handles=handles,
        generated_at=utc_now_iso(),
        correlation_supported=settings.correlation_supported,
    )


def render_query_block(result: ConversionResult) -> str:
    """Render one conversion for console or file output, banner first."""
    lines = [
        f"# {result.banner}",
        f"# rule: {result.catalog_id}",
        f"# backend: {result.backend} ({result.dialect or 'unknown dialect'})",
        f"# status: {result.status}",
        "# production_ready: false",
    ]
    if result.message:
        lines.append(f"# note: {result.message}")
    lines.extend(result.queries or ["# (no query produced)"])
    return "\n".join(lines)


__all__ = [
    "CONVERSION_DEMONSTRATION_BANNER",
    "UNSUPPORTED_MARKERS",
    "BackendHandle",
    "ConversionSet",
    "convert_catalog",
    "convert_rule",
    "load_backend",
    "load_backends",
    "render_query_block",
]
