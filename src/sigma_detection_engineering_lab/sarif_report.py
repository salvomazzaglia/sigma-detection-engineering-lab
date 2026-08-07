"""SARIF 2.1.0 output for detection-engineering quality findings.

SARIF is used here as a code-quality transport, not a vulnerability transport.
Every finding this project emits describes the quality of *detection content* --
a missing sidecar, an unverifiable ATT&CK identifier, a placeholder false
positive. None of them describes an exploitable weakness in software.

That distinction is asserted explicitly rather than left to interpretation:

* no rule carries ``security-severity``, so findings do not appear as security
  alerts or contribute to a security score;
* every rule is tagged ``detection-engineering`` and ``quality``;
* the run and every rule carry properties stating that these are quality
  findings and not vulnerability reports.

Getting this wrong would misrepresent an authoring convention as a security
issue, which is exactly the kind of inflation this project avoids elsewhere.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sigma_detection_engineering_lab import __version__
from sigma_detection_engineering_lab.constants import NO_PRODUCTION_CLAIM
from sigma_detection_engineering_lab.models import ValidationFinding
from sigma_detection_engineering_lab.redaction import redact_findings
from sigma_detection_engineering_lab.severities import to_sarif_level

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
TOOL_NAME = "sigma-detection-engineering-lab"
INFORMATION_URI = "https://github.com/salvomazzaglia/sigma-detection-engineering-lab"

FINDING_KIND = "fail"

QUALITY_PROPERTIES: dict[str, Any] = {
    "category": "detection-engineering-quality",
    "isVulnerabilityFinding": False,
    "note": (
        "These results describe the quality of detection content. They are not "
        "vulnerability findings and carry no security severity."
    ),
}


def _rule_descriptor(code: str, findings: Sequence[ValidationFinding]) -> dict[str, Any]:
    """Build one SARIF reportingDescriptor from all findings sharing a code."""
    sample = findings[0]
    remediation = next((finding.remediation for finding in findings if finding.remediation), None)
    descriptor: dict[str, Any] = {
        "id": code,
        "name": _descriptor_name(code, sample.category.value),
        "shortDescription": {"text": _short_description(sample)},
        "fullDescription": {
            "text": (
                f"Detection-engineering quality check in the {sample.category} category. "
                "This is not a vulnerability finding."
            )
        },
        "defaultConfiguration": {"level": to_sarif_level(sample.severity)},
        "properties": {
            **QUALITY_PROPERTIES,
            "tags": ["detection-engineering", "quality", "sigma", sample.category.value],
            "gate": sample.gate,
        },
    }
    if remediation:
        descriptor["help"] = {"text": remediation}
        descriptor["helpUri"] = INFORMATION_URI
    return descriptor


def _descriptor_name(code: str, category: str) -> str:
    """Build a PascalCase descriptor name, which some SARIF consumers require."""
    suffix = code.replace("-", "").replace("SDEL", "")
    return f"{category.capitalize()}{suffix}"


def _short_description(finding: ValidationFinding) -> str:
    text = finding.message.split(";")[0].strip()
    return text[:200] if text else f"{finding.category} quality finding"


def _result(finding: ValidationFinding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.code,
        "level": to_sarif_level(finding.severity),
        "kind": FINDING_KIND,
        "message": {"text": finding.message},
        "properties": {
            "category": str(finding.category),
            "severity": str(finding.severity),
            "subject": finding.subject,
            "gate": finding.gate,
            "isVulnerabilityFinding": False,
        },
    }
    if finding.path:
        region: dict[str, Any] = {}
        if finding.line is not None and finding.line > 0:
            region["startLine"] = finding.line
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
            }
        }
        if region:
            location["physicalLocation"]["region"] = region
        location["logicalLocations"] = [{"name": finding.subject, "kind": "resource"}]
        result["locations"] = [location]
    else:
        result["locations"] = [
            {"logicalLocations": [{"name": finding.subject, "kind": "resource"}]}
        ]
    return result


def build_sarif(
    findings: Sequence[ValidationFinding],
    *,
    redact: bool = True,
    invocation_command: str = "",
    successful: bool | None = None,
) -> dict[str, Any]:
    """Build the SARIF 2.1.0 document for a set of findings."""
    prepared = redact_findings(findings) if redact else tuple(findings)

    grouped: dict[str, list[ValidationFinding]] = {}
    for finding in prepared:
        grouped.setdefault(finding.code, []).append(finding)

    rules = [_rule_descriptor(code, grouped[code]) for code in sorted(grouped)]
    results = [_result(finding) for finding in prepared]

    invocation: dict[str, Any] = {
        "executionSuccessful": (
            successful if successful is not None else not any(f.is_error for f in prepared)
        ),
    }
    if invocation_command:
        invocation["commandLine"] = invocation_command

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                        "properties": QUALITY_PROPERTIES,
                    }
                },
                "invocations": [invocation],
                "results": results,
                "properties": {
                    **QUALITY_PROPERTIES,
                    "productionReady": False,
                    "disclaimer": NO_PRODUCTION_CLAIM,
                },
            }
        ],
    }


def render_sarif(
    findings: Sequence[ValidationFinding],
    *,
    indent: int = 2,
    redact: bool = True,
    invocation_command: str = "",
    successful: bool | None = None,
) -> str:
    """Render the SARIF document as deterministic JSON text."""
    document = build_sarif(
        findings,
        redact=redact,
        invocation_command=invocation_command,
        successful=successful,
    )
    return json.dumps(document, indent=indent, sort_keys=True, ensure_ascii=False) + "\n"


def write_sarif(
    findings: Sequence[ValidationFinding],
    destination: Path,
    *,
    indent: int = 2,
    redact: bool = True,
    invocation_command: str = "",
    successful: bool | None = None,
) -> Path:
    """Write the SARIF document with LF line endings."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(
            render_sarif(
                findings,
                indent=indent,
                redact=redact,
                invocation_command=invocation_command,
                successful=successful,
            )
        )
    return destination


__all__ = [
    "INFORMATION_URI",
    "QUALITY_PROPERTIES",
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "TOOL_NAME",
    "build_sarif",
    "render_sarif",
    "write_sarif",
]
