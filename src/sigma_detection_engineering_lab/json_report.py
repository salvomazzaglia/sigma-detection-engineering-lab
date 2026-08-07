"""The canonical JSON report and the bundle every other writer consumes.

:class:`ReportBundle` is the single aggregate produced by a run. The HTML, SARIF,
JUnit, and Navigator writers all render from it, so the formats cannot disagree
about what happened.

Two properties are enforced on the way out. Every free-text field passes through
redaction, because reports are committed and published. Every document carries
the banners and an explicit ``production_ready: false``, so a consumer of the
JSON has the same caveats a reader of the HTML does.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sigma_detection_engineering_lab import __version__
from sigma_detection_engineering_lab.attack_catalog import AttackCatalog
from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.constants import (
    ALL_BANNERS,
    CONVERSION_DEMONSTRATION_BANNER,
    COVERAGE_CAVEAT_BANNER,
    NO_EFFICACY_METRICS_NOTE,
    NO_PRODUCTION_CLAIM,
    SYNTHETIC_DATA_BANNER,
    SYNTHETIC_TESTING_BANNER,
)
from sigma_detection_engineering_lab.conversion import ConversionSet
from sigma_detection_engineering_lab.coverage import coverage_payload, fixture_balance
from sigma_detection_engineering_lab.fixture_loader import FixtureSet
from sigma_detection_engineering_lab.metadata_loader import MetadataSet
from sigma_detection_engineering_lab.models import (
    CoverageReport,
    QualityReport,
    TestSummary,
    ValidationFinding,
    ValidationReport,
    utc_now_iso,
)
from sigma_detection_engineering_lab.redaction import redact_findings, redact_value
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.rule_loader import pysigma_status
from sigma_detection_engineering_lab.telemetry import TelemetryCatalog

SCHEMA_ID = "sigma-detection-engineering-lab/report/1.0.0"


@dataclass(frozen=True)
class ReportBundle:
    """Everything one run produced, in one place."""

    config: LabConfig
    catalog: RuleCatalog
    metadata: MetadataSet | None = None
    fixtures: FixtureSet | None = None
    findings: tuple[ValidationFinding, ...] = ()
    test_summary: TestSummary | None = None
    coverage: CoverageReport | None = None
    quality: QualityReport | None = None
    conversions: ConversionSet | None = None
    attack: AttackCatalog | None = None
    telemetry: TelemetryCatalog | None = None
    load_failures: tuple[tuple[str, str], ...] = ()
    command: str = ""
    generated_at: str = field(default_factory=utc_now_iso)

    @property
    def validation(self) -> ValidationReport:
        """Wrap the raw findings in a report object with pass/fail semantics."""
        return ValidationReport(
            findings=self.findings,
            rules_examined=len(self.catalog),
            generated_at=self.generated_at,
        )

    @property
    def passed(self) -> bool:
        """Return whether every executed stage succeeded.

        A stage that did not run cannot make the bundle fail, but a stage that ran
        and failed always does.
        """
        if not self.validation.passed:
            return False
        if self.load_failures:
            return False
        if self.test_summary is not None and not self.test_summary.successful:
            return False
        return not (self.quality is not None and not self.quality.passed)


def _environment() -> dict[str, Any]:
    status = pysigma_status()
    return {
        "tool_version": __version__,
        "pysigma_available": status.available,
        "pysigma_version": status.version,
        "pysigma_error": status.error,
    }


def build_report(bundle: ReportBundle, *, redact: bool = True) -> dict[str, Any]:
    """Assemble the JSON report document from a bundle."""
    findings = redact_findings(bundle.findings) if redact else bundle.findings
    validation = ValidationReport(
        findings=tuple(findings),
        rules_examined=len(bundle.catalog),
        generated_at=bundle.generated_at,
    )

    document: dict[str, Any] = {
        "schema": SCHEMA_ID,
        "generated_at": bundle.generated_at,
        "command": bundle.command,
        "production_ready": False,
        "disclaimer": NO_PRODUCTION_CLAIM,
        "banners": {
            "synthetic_data": SYNTHETIC_DATA_BANNER,
            "synthetic_testing": SYNTHETIC_TESTING_BANNER,
            "conversion": CONVERSION_DEMONSTRATION_BANNER,
            "coverage": COVERAGE_CAVEAT_BANNER,
            "all": list(ALL_BANNERS),
        },
        "environment": _environment(),
        "project": {
            "name": bundle.config.project_name,
            "profile": bundle.config.profile,
            "license": bundle.config.license,
            "authors": list(bundle.config.required_authors),
        },
        "passed": bundle.passed,
        "catalog": bundle.catalog.summary(),
        "validation": validation.to_dict(),
    }

    if bundle.load_failures:
        document["load_failures"] = [
            {"path": path, "message": message} for path, message in bundle.load_failures
        ]

    if bundle.metadata is not None:
        document["metadata"] = bundle.metadata.to_dict()

    if bundle.fixtures is not None:
        document["fixtures"] = bundle.fixtures.to_dict()

    if bundle.test_summary is not None:
        tests = bundle.test_summary.to_dict()
        tests["banner"] = SYNTHETIC_TESTING_BANNER
        tests["totals"] = {
            "total": bundle.test_summary.total,
            "passed": bundle.test_summary.passed,
            "failed": bundle.test_summary.failed,
            "errored": bundle.test_summary.errored,
            "skipped": bundle.test_summary.skipped,
            "unsupported": bundle.test_summary.unsupported,
        }
        document["tests"] = tests

    if bundle.coverage is not None:
        balances = (
            fixture_balance(bundle.catalog, bundle.fixtures) if bundle.fixtures is not None else ()
        )
        document["coverage"] = coverage_payload(
            bundle.coverage, attack=bundle.attack, balances=balances
        )
        document["coverage"]["excluded_metrics_note"] = NO_EFFICACY_METRICS_NOTE

    if bundle.quality is not None:
        document["quality"] = bundle.quality.to_dict()

    if bundle.conversions is not None:
        document["conversions"] = bundle.conversions.to_dict()

    if bundle.attack is not None:
        document["attack_catalog"] = bundle.attack.to_dict()

    if bundle.telemetry is not None:
        document["telemetry_catalog"] = {
            "available": bundle.telemetry.available,
            "source_count": len(bundle.telemetry.sources),
            "load_error": bundle.telemetry.load_error,
        }

    return redact_value(document, include_suspicious_commands=False) if redact else document


def render_json(bundle: ReportBundle, *, indent: int = 2, redact: bool = True) -> str:
    """Render the report as deterministic JSON text."""
    document = build_report(bundle, redact=redact)
    return json.dumps(document, indent=indent, sort_keys=True, ensure_ascii=False) + "\n"


def write_json_report(
    bundle: ReportBundle,
    destination: Path,
    *,
    indent: int = 2,
    redact: bool = True,
) -> Path:
    """Write the JSON report with LF line endings."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_json(bundle, indent=indent, redact=redact))
    return destination


def write_document(document: Any, destination: Path, *, indent: int = 2) -> Path:
    """Write any JSON-serialisable document deterministically."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(document, indent=indent, sort_keys=True, ensure_ascii=False))
        handle.write("\n")
    return destination


def findings_to_csv(findings: Sequence[ValidationFinding]) -> str:
    """Render findings as CSV for spreadsheet review."""
    import csv
    import io

    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        ["code", "severity", "category", "subject", "path", "gate", "message", "remediation"]
    )
    for finding in redact_findings(findings):
        writer.writerow(
            [
                finding.code,
                str(finding.severity),
                str(finding.category),
                finding.subject,
                finding.path or "",
                finding.gate or "",
                finding.message,
                finding.remediation or "",
            ]
        )
    return buffer.getvalue()


__all__ = [
    "SCHEMA_ID",
    "ReportBundle",
    "build_report",
    "findings_to_csv",
    "render_json",
    "write_document",
    "write_json_report",
]
