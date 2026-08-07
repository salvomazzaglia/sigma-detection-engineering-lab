"""Shared fixtures and builders for the offline test suite.

Every helper here builds content in memory or under ``tmp_path``. Nothing in the
suite reaches the network, a SIEM, or host telemetry, which mirrors the guarantee
the package itself makes.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sigma_detection_engineering_lab.config import LabConfig, load_config
from sigma_detection_engineering_lab.event_model import SyntheticEvent
from sigma_detection_engineering_lab.fixture_loader import FixtureSet, load_fixtures
from sigma_detection_engineering_lab.metadata_loader import (
    MetadataSet,
    assign_catalog_ids,
    load_metadata,
)
from sigma_detection_engineering_lab.models import (
    AttackMapping,
    CorrelationSequence,
    FindingCategory,
    FixtureCase,
    FixtureKind,
    LogSource,
    Rule,
    SidecarMetadata,
    ValidationFinding,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.rule_loader import load_rules
from sigma_detection_engineering_lab.severities import Severity
from sigma_detection_engineering_lab.statuses import Maturity, SigmaStatus

PROJECT_ROOT = Path(__file__).resolve().parents[1]

BASE_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

DEMO_RULE_UUID = "6f1a2b3c-4d5e-4f60-9a71-2b3c4d5e6f70"

MINIMAL_CONFIG: dict[str, Any] = {
    "schema_version": "1.0.0",
    "project_name": "sdel-test-project",
    "paths": {
        "rules": "rules",
        "metadata": "metadata/rules",
        "fixtures": "fixtures",
        "attack_data": "data/attack",
        "examples": "examples",
        "schemas": "schemas",
        "temp_output": "temp",
    },
    "limits": {
        "max_file_bytes": 1048576,
        "max_yaml_depth": 32,
        "max_yaml_nodes": 5000,
        "max_yaml_aliases": 0,
        "max_scalar_length": 8192,
        "max_mapping_size": 512,
        "max_sequence_length": 512,
        "max_path_length": 4096,
        "max_regex_length": 256,
        "max_events_per_fixture": 200,
        "max_correlation_sequence_events": 100,
        "allow_symlinks": False,
    },
    "authors": {"required": ["Salvatore Mazzaglia"]},
    "license": "MIT",
    "allowed_sigma_statuses": ["experimental", "test"],
    "blocked_sigma_statuses_main_catalog": ["stable"],
    "allowed_maturity": ["experimental", "tested-synthetic"],
    "synthetic_hosts": ["SYNTHETIC-HOST-01", "SYNTHETIC-DC01"],
    "synthetic_users": ["synthetic-user", "synthetic-admin"],
}

SAMPLE_RULE_TEXT = """\
title: 'Synthetic Process Launched From Staging Path'
id: 11111111-2222-4333-8444-555555555555
status: experimental
description: >-
    A synthetic demonstration rule used by the offline test suite to exercise the rule
    loader, the matcher, and the report writers end to end.
references:
    - 'https://attack.mitre.org/techniques/T1204/002/'
author: 'Salvatore Mazzaglia'
date: 2026-08-01
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_staging:
        Image|startswith: 'C:\\\\Synthetic\\\\Staging\\\\'
    condition: selection_staging
falsepositives:
    - >-
        Packaging pipelines that build into the synthetic staging directory and run
        smoke tests before the artefact is signed.
level: medium
license: MIT
"""

SAMPLE_SIDECAR: dict[str, Any] = {
    "schema_version": "1.0.0",
    "catalog_id": "SDEL-TST-001",
    "sigma_rule_id": "11111111-2222-4333-8444-555555555555",
    "title": "Synthetic Process Launched From Staging Path",
    "detection_hypothesis": (
        "If tooling is staged in a directory no managed installer writes to, the "
        "resulting process creation event shows an Image path rooted there."
    ),
    "platform": "windows",
    "rule_family": "windows",
    "maturity": "experimental",
    "required_logs": ["Windows process creation telemetry"],
    "required_channels": ["Microsoft-Windows-Sysmon/Operational"],
    "required_fields": ["Image"],
    "optional_fields": ["CommandLine"],
    "attack_techniques": [{"id": "T1204.002", "name": "User Execution: Malicious File"}],
    "attack_tactics": [{"id": "TA0002", "name": "Execution"}],
    "supported_backends": ["splunk"],
    "minimum_positive_tests": 1,
    "minimum_negative_tests": 1,
    "author": "Salvatore Mazzaglia",
    "license": "MIT",
    "synthetic_fixtures_only": True,
}


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #


def make_event(
    event_id: str = "EVT-001",
    *,
    fields: Mapping[str, Any] | None = None,
    timestamp: datetime | None = None,
    offset_seconds: int = 0,
    host: str = "SYNTHETIC-HOST-01",
    user: str | None = None,
    category: str | None = "process_creation",
    product: str | None = "windows",
    service: str | None = None,
    channel: str | None = None,
    provider: str | None = None,
    platform: str | None = None,
    scenario: str = "",
    notes: str = "",
    labels: tuple[str, ...] = (),
    event_code: str | None = None,
) -> SyntheticEvent:
    """Build a synthetic event with sensible offline defaults."""
    return SyntheticEvent(
        event_id=event_id,
        timestamp=timestamp or (BASE_TIME + timedelta(seconds=offset_seconds)),
        host=host,
        user=user,
        category=category,
        product=product,
        service=service,
        event_code=event_code,
        channel=channel,
        provider=provider,
        platform=platform,
        scenario=scenario,
        notes=notes,
        fields=dict(fields or {}),
        labels=labels,
    )


def make_rule(
    catalog_id: str = "SDEL-TST-001",
    *,
    rule_id: str = "11111111-2222-4333-8444-555555555555",
    title: str = "Synthetic Test Rule",
    detection: Mapping[str, Any] | None = None,
    logsource: LogSource | None = None,
    status: SigmaStatus = SigmaStatus.EXPERIMENTAL,
    level: Severity = Severity.MEDIUM,
    author: str = "Salvatore Mazzaglia",
    license_value: str | None = "MIT",
    date: str | None = "2026-08-01",
    modified: str | None = None,
    tags: tuple[str, ...] = ("attack.execution", "attack.t1204.002"),
    references: tuple[str, ...] = ("https://attack.mitre.org/techniques/T1204/002/",),
    falsepositives: tuple[str, ...] = (
        "Packaging pipelines that stage build artefacts in the same directory.",
    ),
    description: str = (
        "A synthetic rule used by the offline test suite for structural validation."
    ),
    relative_path: str = "rules/windows/process_creation/synthetic_test_rule.yml",
    is_correlation: bool = False,
    correlation: Mapping[str, Any] | None = None,
    documents: Sequence[Mapping[str, Any]] = (),
    name: str | None = None,
    raw_text: str = "",
) -> Rule:
    """Build a :class:`Rule` directly, bypassing YAML parsing."""
    return Rule(
        catalog_id=catalog_id,
        rule_id=rule_id,
        title=title,
        path=Path(relative_path),
        relative_path=relative_path,
        description=description,
        status=status,
        level=level,
        author=author,
        license=license_value,
        date=date,
        modified=modified,
        name=name,
        references=references,
        tags=tags,
        falsepositives=falsepositives,
        logsource=logsource
        if logsource is not None
        else LogSource(category="process_creation", product="windows"),
        detection=dict(
            detection
            if detection is not None
            else {
                "selection": {"Image|endswith": "\\synthetic.exe"},
                "condition": "selection",
            }
        ),
        is_correlation=is_correlation,
        correlation=dict(correlation) if correlation is not None else None,
        documents=tuple(dict(document) for document in documents),
        raw_text=raw_text,
    )


def make_sidecar(
    catalog_id: str = "SDEL-TST-001",
    *,
    rule_id: str = "11111111-2222-4333-8444-555555555555",
    maturity: Maturity = Maturity.EXPERIMENTAL,
    attack_mapping: AttackMapping | None = None,
    detection_hypothesis: str = (
        "Staging a binary outside managed installation directories produces a "
        "process creation event whose Image path is rooted in that directory."
    ),
    telemetry_requirements: Sequence[Any] = (),
    required_fields: tuple[str, ...] = ("Image",),
    required_channels: tuple[str, ...] = (),
    synthetic_only: bool = True,
    relative_path: str | None = None,
) -> SidecarMetadata:
    """Build a :class:`SidecarMetadata` directly."""
    path = Path(relative_path or f"metadata/rules/{catalog_id}.json")
    return SidecarMetadata(
        catalog_id=catalog_id,
        rule_id=rule_id,
        maturity=maturity,
        path=path,
        relative_path=path.as_posix(),
        title="Synthetic Test Rule",
        detection_hypothesis=detection_hypothesis,
        telemetry_requirements=tuple(telemetry_requirements),
        attack_mapping=attack_mapping
        if attack_mapping is not None
        else AttackMapping(techniques=("T1204.002",), tactics=("TA0002",)),
        required_fields=required_fields,
        required_channels=required_channels,
        synthetic_only=synthetic_only,
    )


def make_case(
    catalog_id: str = "SDEL-TST-001",
    *,
    kind: FixtureKind = FixtureKind.POSITIVE,
    event: SyntheticEvent | None = None,
    case_id: str | None = None,
    source_path: str = "fixtures/rules/SDEL-TST-001/positive/case_01.jsonl",
) -> FixtureCase:
    """Build one fixture case."""
    resolved = event or make_event(fields={"Image": "C:\\Synthetic\\synthetic.exe"})
    return FixtureCase(
        case_id=case_id or f"{catalog_id}::{kind.value}::{resolved.event_id}",
        catalog_id=catalog_id,
        kind=kind,
        event=resolved,
        source_path=source_path,
    )


def make_sequence(
    catalog_id: str = "SDEL-COR-001",
    *,
    kind: FixtureKind = FixtureKind.POSITIVE,
    events: Sequence[SyntheticEvent] = (),
    sequence_id: str | None = None,
    source_path: str = "fixtures/correlation/SDEL-COR-001/positive/sequence_01.jsonl",
) -> CorrelationSequence:
    """Build one correlation sequence."""
    return CorrelationSequence(
        sequence_id=sequence_id or f"{catalog_id}::{kind.value}::sequence_01",
        catalog_id=catalog_id,
        kind=kind,
        events=tuple(events),
        source_path=source_path,
    )


def make_finding(
    code: str = "SDEL-TST-001",
    *,
    severity: Severity = Severity.MEDIUM,
    category: FindingCategory = FindingCategory.STRUCTURE,
    subject: str = "SDEL-TST-001",
    message: str = "synthetic finding used by the offline test suite",
    path: str | None = "rules/windows/process_creation/synthetic_test_rule.yml",
    gate: str | None = None,
    remediation: str | None = None,
    line: int | None = None,
) -> ValidationFinding:
    """Build one validation finding."""
    return ValidationFinding(
        code=code,
        category=category,
        severity=severity,
        subject=subject,
        message=message,
        path=path,
        line=line,
        gate=gate,
        remediation=remediation,
    )


def write_json(path: Path, payload: Any) -> Path:
    """Write JSON with LF endings, creating parents."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return path


def write_jsonl_records(path: Path, records: Sequence[Mapping[str, Any]]) -> Path:
    """Write raw JSONL records, creating parents."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False))
            handle.write("\n")
    return path


def event_record(
    event_id: str = "EVT-001",
    *,
    fields: Mapping[str, Any] | None = None,
    offset_seconds: int = 0,
    host: str = "SYNTHETIC-HOST-01",
    user: str | None = "synthetic-user",
    category: str | None = "process_creation",
    product: str | None = "windows",
    service: str | None = None,
) -> dict[str, Any]:
    """Build a JSONL-shaped record for a synthetic event."""
    logsource = {
        key: value
        for key, value in (
            ("category", category),
            ("product", product),
            ("service", service),
        )
        if value is not None
    }
    record: dict[str, Any] = {
        "event_id": event_id,
        "timestamp_utc": (BASE_TIME + timedelta(seconds=offset_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3]
        + "Z",
        "host": host,
        "synthetic": True,
        "fields": dict(fields or {"Image": "C:\\Synthetic\\synthetic.exe"}),
    }
    if user is not None:
        record["user"] = user
    if logsource:
        record["logsource"] = logsource
    return record


def build_project(
    root: Path,
    *,
    config: Mapping[str, Any] | None = None,
    rules: Mapping[str, str] | None = None,
    sidecars: Mapping[str, Mapping[str, Any]] | None = None,
    attack: Mapping[str, Any] | None = None,
    telemetry: Mapping[str, Any] | None = None,
    quality_gates: Mapping[str, Any] | None = None,
    conversion_backends: Mapping[str, Any] | None = None,
    evaluator_profile: Mapping[str, Any] | None = None,
) -> Path:
    """Materialise a miniature project tree under ``root``.

    Returns the root, ready to be passed to :func:`load_config`.
    """
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text("[project]\nname = 'sdel-test'\n", encoding="utf-8")
    (root / "VERSION").write_text("1.0.0\n", encoding="utf-8")

    write_json(root / "config" / "default.config.json", dict(config or MINIMAL_CONFIG))

    for relative, text in (rules or {}).items():
        target = root / "rules" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")

    for name, payload in (sidecars or {}).items():
        write_json(root / "metadata" / "rules" / f"{name}.json", dict(payload))

    if attack is not None:
        write_json(root / "data" / "attack" / "enterprise-attack-subset.json", dict(attack))
    if telemetry is not None:
        write_json(root / "config" / "telemetry-catalog.json", dict(telemetry))
    if quality_gates is not None:
        write_json(root / "config" / "quality-gates.json", dict(quality_gates))
    if conversion_backends is not None:
        write_json(root / "config" / "conversion-backends.json", dict(conversion_backends))
    if evaluator_profile is not None:
        write_json(root / "config" / "evaluator-profile.json", dict(evaluator_profile))
    return root


ATTACK_SUBSET: dict[str, Any] = {
    "schema_version": "1.0.0",
    "attack_version": "19.1",
    "domain": "enterprise-attack",
    "tactics": [
        {
            "id": "TA0002",
            "name": "Execution",
            "shortname": "execution",
            "sigma_tag": "attack.execution",
        },
        {
            "id": "TA0006",
            "name": "Credential Access",
            "shortname": "credential-access",
            "sigma_tag": "attack.credential-access",
        },
    ],
    "techniques": [
        {
            "id": "T1204.002",
            "name": "User Execution: Malicious File",
            "is_subtechnique": True,
            "parent_technique": "T1204",
            "tactics": ["TA0002"],
        },
        {
            "id": "T1204",
            "name": "User Execution",
            "is_subtechnique": False,
            "tactics": ["TA0002"],
        },
        {
            "id": "T1003.001",
            "name": "OS Credential Dumping: LSASS Memory",
            "is_subtechnique": True,
            "parent_technique": "T1003",
            "tactics": ["TA0006"],
        },
        {
            "id": "T1999",
            "name": "Retired Demonstration Technique",
            "tactics": ["TA0002"],
            "deprecated": True,
        },
    ],
    "detection_strategies": [{"id": "DET0001", "name": "Demonstration Strategy"}],
    "analytics": [{"id": "AN0001", "name": "Demonstration Analytic"}],
    "data_components": [{"id": "DC0001", "name": "Demonstration Data Component"}],
}

TELEMETRY_CATALOG: dict[str, Any] = {
    "schema_version": "1.0.0",
    "profiles": {
        "win_process_creation": {
            "platform": "windows",
            "logsource": {"category": "process_creation", "product": "windows"},
            "required_logs": ["Windows process creation telemetry"],
            "channels": ["Microsoft-Windows-Sysmon/Operational"],
            "providers": ["Microsoft-Windows-Sysmon"],
            "fields": ["Image", "CommandLine", "ParentImage"],
        }
    },
}


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def pytest_pycollect_makeitem(collector: Any, name: str, obj: object) -> Any:
    """Stop pytest collecting production classes named ``Test*``.

    The package exports ``TestResult``, ``TestSummary``, ``TestOutcome``, and
    ``TestRunOptions``. Importing any of them into a test module would otherwise
    be collected as a test class and reported as a collection error.
    """
    if isinstance(obj, type) and getattr(obj, "__module__", "").startswith(
        "sigma_detection_engineering_lab"
    ):
        return []
    return None


@pytest.fixture(scope="session")
def project_root() -> Path:
    """The real repository root, used by read-only integration tests."""
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def real_config() -> LabConfig:
    """The real project configuration, loaded once."""
    return load_config(PROJECT_ROOT)


@pytest.fixture(scope="session")
def real_catalog(real_config: LabConfig) -> RuleCatalog:
    """The real rule catalog with catalog identifiers bound from sidecars."""
    metadata = load_metadata(real_config)
    outcome = load_rules(real_config)
    rules, _ = assign_catalog_ids(outcome.rules, metadata)
    return RuleCatalog(rules)


@pytest.fixture(scope="session")
def real_metadata(real_config: LabConfig) -> MetadataSet:
    """Every sidecar in the real project."""
    return load_metadata(real_config)


@pytest.fixture(scope="session")
def real_fixtures(real_config: LabConfig) -> FixtureSet:
    """Every fixture in the real project."""
    return load_fixtures(real_config)


@pytest.fixture(scope="session")
def real_summary(real_catalog: RuleCatalog, real_fixtures: FixtureSet) -> Any:
    """One behavioral run over the real catalog, shared by integration tests."""
    from sigma_detection_engineering_lab.behavioral_testing import run_catalog

    return run_catalog(real_catalog, real_fixtures)


@pytest.fixture(scope="session")
def real_attack(real_config: LabConfig) -> Any:
    """The ATT&CK subset vendored into the real repository."""
    from sigma_detection_engineering_lab.attack_catalog import load_attack_catalog

    return load_attack_catalog(real_config)


@pytest.fixture
def tiny_project(tmp_path: Path) -> Path:
    """A minimal, valid project tree under ``tmp_path``."""
    return build_project(
        tmp_path / "project",
        rules={"windows/process_creation/synthetic_staging_execution.yml": SAMPLE_RULE_TEXT},
        sidecars={"SDEL-TST-001": SAMPLE_SIDECAR},
        attack=ATTACK_SUBSET,
        telemetry=TELEMETRY_CATALOG,
    )


@pytest.fixture
def tiny_config(tiny_project: Path) -> LabConfig:
    """Configuration loaded from :func:`tiny_project`."""
    return load_config(tiny_project)


@pytest.fixture
def tiny_catalog(tiny_config: LabConfig) -> RuleCatalog:
    """Catalog built from the miniature project, with identifiers bound."""
    metadata = load_metadata(tiny_config)
    outcome = load_rules(tiny_config)
    rules, _ = assign_catalog_ids(outcome.rules, metadata)
    return RuleCatalog(rules)


@pytest.fixture
def simple_catalog() -> RuleCatalog:
    """A one-rule catalog built entirely in memory."""
    return RuleCatalog([make_rule()])


@pytest.fixture
def empty_fixture_set() -> FixtureSet:
    """A fixture set with no cases and no sequences."""
    return FixtureSet()
