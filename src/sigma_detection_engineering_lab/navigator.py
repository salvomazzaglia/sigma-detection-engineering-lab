"""ATT&CK Navigator layer output, layer format 4.5.

The layer shows which techniques the catalog claims to address. Two conventions
keep that claim honest.

Only techniques present in the vendored ATT&CK catalog are emitted. An
unverifiable identifier is dropped from the layer and reported separately,
because a Navigator layer is read as a coverage statement and an invented
technique would inflate it silently.

Technique colour encodes rule count, not detection confidence. A technique with
five untested rules is not better covered than one with a single tested rule, and
the layer legend says so.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from sigma_detection_engineering_lab import __version__
from sigma_detection_engineering_lab.attack_catalog import AttackCatalog
from sigma_detection_engineering_lab.constants import COVERAGE_CAVEAT_BANNER
from sigma_detection_engineering_lab.metadata_loader import MetadataSet
from sigma_detection_engineering_lab.models import CoverageReport
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog

LAYER_VERSION: Final[str] = "4.5"
NAVIGATOR_VERSION: Final[str] = "5.1.0"
DEFAULT_DOMAIN: Final[str] = "enterprise-attack"

GRADIENT_COLORS: Final[tuple[str, ...]] = ("#deebf7", "#3182bd")

LEGEND: Final[tuple[tuple[str, str], ...]] = (
    ("1 rule", "#deebf7"),
    ("2 rules", "#9ecae1"),
    ("3 or more rules", "#3182bd"),
)


def _color_for_count(count: int) -> str:
    if count >= 3:
        return "#3182bd"
    if count == 2:
        return "#9ecae1"
    return "#deebf7"


def _rules_for_technique(metadata: MetadataSet, technique_id: str) -> tuple[str, ...]:
    needle = technique_id.strip().upper()
    return tuple(
        sorted(
            sidecar.catalog_id
            for sidecar in metadata.sidecars
            if any(item.strip().upper() == needle for item in sidecar.attack_mapping.techniques)
        )
    )


def build_layer(
    coverage: CoverageReport,
    metadata: MetadataSet,
    attack: AttackCatalog,
    *,
    catalog: RuleCatalog | None = None,
    name: str = "sigma-detection-engineering-lab coverage",
    description: str | None = None,
    domain: str | None = None,
) -> dict[str, Any]:
    """Build an ATT&CK Navigator layer document.

    Args:
        coverage: Coverage report supplying technique counts.
        metadata: Sidecars, used to name the rules behind each technique.
        attack: Vendored catalog, used to verify every technique before it is
            emitted.
        catalog: Optional rule catalog, used only for the layer description.
        name: Layer name shown in Navigator.
        description: Layer description; a caveat-bearing default is used if omitted.
        domain: ATT&CK domain, defaulting to the catalog's own.
    """
    techniques: list[dict[str, Any]] = []
    skipped: list[str] = []

    for technique_id, count in sorted(coverage.technique_counts.items()):
        verified = attack.get_technique(technique_id) if attack.is_available else None
        if attack.is_available and verified is None:
            skipped.append(technique_id)
            continue

        rules = _rules_for_technique(metadata, technique_id)
        comment_parts = [f"{count} rule(s) in this catalog"]
        if rules:
            comment_parts.append("; ".join(rules))
        comment_parts.append(COVERAGE_CAVEAT_BANNER)

        techniques.append(
            {
                "techniqueID": technique_id.strip().upper(),
                "score": count,
                "color": _color_for_count(count),
                "comment": " | ".join(comment_parts),
                "enabled": True,
                "showSubtechniques": "." in technique_id,
                "metadata": [
                    {"name": "rule_count", "value": str(count)},
                    {"name": "rules", "value": ", ".join(rules) or "unknown"},
                ],
                "links": [],
            }
        )

    total_rules = len(catalog) if catalog is not None else coverage.total_rules
    default_description = (
        f"Techniques addressed by {total_rules} original Sigma rule(s). "
        f"Score is the number of rules mapped to a technique, not a measure of "
        f"detection confidence or environmental coverage. {COVERAGE_CAVEAT_BANNER}"
    )

    layer: dict[str, Any] = {
        "name": name,
        "versions": {
            "attack": attack.attack_version or "unknown",
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": domain or attack.domain or DEFAULT_DOMAIN,
        "description": description or default_description,
        "filters": {"platforms": []},
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": list(GRADIENT_COLORS),
            "minValue": 0,
            "maxValue": max((entry["score"] for entry in techniques), default=1),
        },
        "legendItems": [{"label": label, "color": color} for label, color in LEGEND],
        "metadata": [
            {"name": "generator", "value": f"sigma-detection-engineering-lab {__version__}"},
            {"name": "generated_at", "value": coverage.generated_at},
            {"name": "caveat", "value": COVERAGE_CAVEAT_BANNER},
            {"name": "verified_against", "value": attack.attack_version or "unverified"},
        ],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }

    if skipped:
        layer["metadata"].append(
            {
                "name": "omitted_unverified_techniques",
                "value": ", ".join(sorted(skipped)),
            }
        )
    return layer


def unverified_techniques(coverage: CoverageReport, attack: AttackCatalog) -> tuple[str, ...]:
    """Return mapped techniques the vendored catalog does not confirm."""
    if not attack.is_available:
        return tuple(sorted(coverage.technique_counts))
    return tuple(
        sorted(
            technique_id
            for technique_id in coverage.technique_counts
            if attack.get_technique(technique_id) is None
        )
    )


def render_layer(layer: Mapping[str, Any], *, indent: int = 2) -> str:
    """Render a layer document as deterministic JSON text."""
    return json.dumps(layer, indent=indent, sort_keys=True, ensure_ascii=False) + "\n"


def write_layer(layer: Mapping[str, Any], destination: Path, *, indent: int = 2) -> Path:
    """Write the Navigator layer with LF line endings."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_layer(layer, indent=indent))
    return destination


def build_and_write(
    coverage: CoverageReport,
    metadata: MetadataSet,
    attack: AttackCatalog,
    destination: Path,
    *,
    catalog: RuleCatalog | None = None,
) -> Path:
    """Build a layer and write it in one step."""
    layer = build_layer(coverage, metadata, attack, catalog=catalog)
    return write_layer(layer, destination)


def layer_summary(layer: Mapping[str, Any]) -> dict[str, Any]:
    """Summarise a layer for console output."""
    techniques: Sequence[Any] = layer.get("techniques", [])
    return {
        "technique_count": len(techniques),
        "layer_version": layer.get("versions", {}).get("layer"),
        "attack_version": layer.get("versions", {}).get("attack"),
        "domain": layer.get("domain"),
    }


__all__ = [
    "DEFAULT_DOMAIN",
    "GRADIENT_COLORS",
    "LAYER_VERSION",
    "LEGEND",
    "NAVIGATOR_VERSION",
    "build_and_write",
    "build_layer",
    "layer_summary",
    "render_layer",
    "unverified_techniques",
    "write_layer",
]
