"""Command-line interface for the offline detection-engineering laboratory.

Nine commands are exposed: ``validate``, ``test``, ``list-rules``, ``explain``,
``coverage``, ``convert``, ``compare``, ``generate-demo``, and ``version``.

Exit codes are part of the contract, because this runs in CI:

===== ==========================================================
Code  Meaning
===== ==========================================================
0     Everything requested succeeded.
1     The analysis ran and something failed: a blocking finding,
      a failing behavioral test, or a failing quality gate.
2     The command line itself was wrong.
3     The laboratory refused to run: bad config, unsafe path,
      unreadable catalog.
===== ==========================================================

A failing rule and a broken installation are different problems, so they never
share an exit code.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TextIO

from sigma_detection_engineering_lab import (
    CLI_NAME,
    __version__,
    attack_mapping,
    console,
    convention_validation,
    redaction,
    sigma_validation,
    telemetry,
)
from sigma_detection_engineering_lab.attack_catalog import AttackCatalog, load_attack_catalog
from sigma_detection_engineering_lab.behavioral_testing import (
    TestRunOptions,
    failing_results,
    run_catalog,
)
from sigma_detection_engineering_lab.comparison import compare_files
from sigma_detection_engineering_lab.condition_parser import parse_condition
from sigma_detection_engineering_lab.config import (
    DEFAULT_PROFILE,
    LabConfig,
    load_config,
    load_conversion_config,
    load_evaluator_profile,
    load_upstream_versions,
)
from sigma_detection_engineering_lab.constants import (
    CONVERSION_DEMONSTRATION_BANNER,
    COVERAGE_CAVEAT_BANNER,
    NO_EFFICACY_METRICS_NOTE,
    NO_PRODUCTION_CLAIM,
    SYNTHETIC_DATA_BANNER,
    SYNTHETIC_TESTING_BANNER,
)
from sigma_detection_engineering_lab.conversion import convert_catalog, render_query_block
from sigma_detection_engineering_lab.coverage import build_coverage, technique_gaps
from sigma_detection_engineering_lab.errors import SdelError
from sigma_detection_engineering_lab.event_matcher import (
    MatchOptions,
    build_rule_matcher,
)
from sigma_detection_engineering_lab.event_model import SyntheticEvent
from sigma_detection_engineering_lab.fixture_loader import FixtureSet, load_fixtures, write_jsonl
from sigma_detection_engineering_lab.html_report import write_html
from sigma_detection_engineering_lab.json_report import (
    ReportBundle,
    findings_to_csv,
    render_json,
    write_document,
    write_json_report,
)
from sigma_detection_engineering_lab.junit_report import write_junit
from sigma_detection_engineering_lab.metadata_loader import (
    MetadataSet,
    assign_catalog_ids,
    load_metadata,
)
from sigma_detection_engineering_lab.metadata_loader import (
    validate_metadata as validate_metadata_set,
)
from sigma_detection_engineering_lab.models import (
    FixtureKind,
    Severity,
    ValidationFinding,
)
from sigma_detection_engineering_lab.navigator import (
    build_layer,
    unverified_techniques,
    write_layer,
)
from sigma_detection_engineering_lab.quality_gates import (
    GateInputs,
    apply_gates,
    load_quality_gates,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog, RuleFilter
from sigma_detection_engineering_lab.rule_loader import load_rules, pysigma_status
from sigma_detection_engineering_lab.sarif_report import write_sarif
from sigma_detection_engineering_lab.severities import parse_severity
from sigma_detection_engineering_lab.statuses import parse_status
from sigma_detection_engineering_lab.telemetry import load_telemetry_catalog

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_REFUSED = 3


@dataclass(frozen=True)
class Workspace:
    """Everything loaded before any analysis runs."""

    config: LabConfig
    match_options: MatchOptions
    catalog: RuleCatalog
    metadata: MetadataSet
    fixtures: FixtureSet
    attack: AttackCatalog
    load_failures: tuple[tuple[str, str], ...]
    binding_findings: tuple[ValidationFinding, ...]


def _open_workspace(args: argparse.Namespace, *, load_fixture_data: bool = True) -> Workspace:
    """Load config, rules, sidecars, and fixtures, and settle rule identity.

    Sidecars are loaded before the catalog is built, because a rule's catalog
    identifier comes from the sidecar that claims its UUID. Building the catalog
    first would index every rule under a filename-derived placeholder.
    """
    config = load_config(getattr(args, "root", None), profile=args.profile)
    profile = load_evaluator_profile(config)
    match_options = MatchOptions.from_profile(profile)

    metadata = load_metadata(config, directory=_override(config, args, "metadata"))
    outcome = load_rules(config, directory=_override(config, args, "rules"))
    rules, binding_findings = assign_catalog_ids(outcome.rules, metadata)
    catalog = RuleCatalog(rules)

    fixtures = (
        load_fixtures(config, fixtures_root=_override(config, args, "fixtures"))
        if load_fixture_data
        else FixtureSet(banner=config.synthetic_banner)
    )

    return Workspace(
        config=config,
        match_options=match_options,
        catalog=catalog,
        metadata=metadata,
        fixtures=fixtures,
        attack=load_attack_catalog(config),
        load_failures=outcome.failures,
        binding_findings=tuple(binding_findings),
    )


def _override(config: LabConfig, args: argparse.Namespace, name: str) -> Path | None:
    """Resolve a per-run directory override against the project root."""
    value = getattr(args, name, None)
    if not value:
        return None
    candidate = Path(value)
    return candidate if candidate.is_absolute() else config.root / candidate


def _collect_findings(workspace: Workspace, *, run_pysigma: bool = True) -> list[ValidationFinding]:
    """Run every validator over the workspace and return the combined findings."""
    findings: list[ValidationFinding] = list(workspace.binding_findings)

    for path, message in workspace.load_failures:
        findings.append(
            ValidationFinding(
                code="SDEL-LOAD-001",
                category=sigma_validation.FindingCategory.STRUCTURE,
                severity=Severity.CRITICAL,
                subject=path,
                message=f"rule could not be loaded: {message}",
                path=path,
                gate="safe_yaml_load",
            )
        )

    for path, message in workspace.fixtures.errors:
        findings.append(
            ValidationFinding(
                code="SDEL-FIX-001",
                category=sigma_validation.FindingCategory.FIXTURE,
                severity=Severity.HIGH,
                subject=path,
                message=f"fixture could not be loaded: {message}",
                path=path,
                gate="all_positive_must_match",
            )
        )

    findings.extend(workspace.catalog.uniqueness_findings())
    findings.extend(
        sigma_validation.validate_catalog(
            workspace.catalog,
            config=workspace.config,
            options=workspace.match_options,
            run_pysigma=run_pysigma,
        )
    )
    findings.extend(
        convention_validation.validate_catalog(workspace.catalog, config=workspace.config)
    )
    findings.extend(
        validate_metadata_set(workspace.metadata, workspace.catalog, config=workspace.config)
    )
    findings.extend(
        attack_mapping.validate_catalog(workspace.catalog, workspace.metadata, workspace.attack)
    )
    findings.extend(
        telemetry.validate_catalog(
            workspace.catalog,
            workspace.metadata,
            load_telemetry_catalog(workspace.config),
        )
    )
    findings.extend(redaction.scan_rules_for_secrets(workspace.catalog))
    findings.extend(redaction.scan_fixtures_for_secrets(workspace.fixtures))
    findings.extend(redaction.scan_fixtures_for_real_data(workspace.fixtures, workspace.config))
    return findings


def _run_tests(workspace: Workspace, only: Sequence[str] | None = None) -> Any:
    options = TestRunOptions(match_options=workspace.match_options)
    return run_catalog(workspace.catalog, workspace.fixtures, options=options, only=only)


def _print_banners(stream: TextIO) -> None:
    console.write(console.banner(SYNTHETIC_DATA_BANNER, stream=stream), stream=stream)


def _write_reports(
    bundle: ReportBundle,
    args: argparse.Namespace,
    stream: TextIO,
) -> None:
    """Write whichever report formats the caller asked for."""
    written: list[str] = []

    if getattr(args, "json_out", None):
        written.append(str(write_json_report(bundle, Path(args.json_out))))
    if getattr(args, "html_out", None):
        written.append(str(write_html(bundle, Path(args.html_out))))
    if getattr(args, "sarif_out", None):
        written.append(
            str(
                write_sarif(
                    bundle.findings,
                    Path(args.sarif_out),
                    invocation_command=bundle.command,
                    successful=bundle.passed,
                )
            )
        )
    if getattr(args, "junit_out", None) and bundle.test_summary is not None:
        written.append(str(write_junit(bundle.test_summary, Path(args.junit_out))))
    if getattr(args, "csv_out", None):
        destination = Path(args.csv_out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(findings_to_csv(bundle.findings))
        written.append(str(destination))

    if written:
        console.blank(stream=stream)
        console.write("Reports written:", stream=stream)
        console.write(console.bullet_list(written), stream=stream)


def _finding_rows(findings: Sequence[ValidationFinding], limit: int) -> list[list[str]]:
    ordered = sorted(
        findings,
        key=lambda item: (-item.severity.rank, item.code, item.subject),
    )
    return [
        [
            str(finding.severity),
            finding.code,
            finding.subject,
            finding.message,
        ]
        for finding in ordered[:limit]
    ]


def _severity_counts(findings: Sequence[ValidationFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        key = str(finding.severity)
        counts[key] = counts.get(key, 0) + 1
    return counts


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def cmd_validate(args: argparse.Namespace, stream: TextIO) -> int:
    """Validate the catalog and apply the quality gates."""
    workspace = _open_workspace(args)
    findings = _collect_findings(workspace, run_pysigma=not args.no_pysigma)

    # Several quality gates judge behavioral results and conversion status. Skipping
    # those stages does not make their gates pass, it makes them unproven, so both
    # run by default and a validate run is a complete verdict.
    summary = None if args.skip_tests else _run_tests(workspace)
    conversions = (
        None
        if args.skip_conversion
        else convert_catalog(workspace.catalog, config=workspace.config)
    )

    coverage_report = build_coverage(
        workspace.catalog, workspace.metadata, workspace.fixtures, summary
    )

    gate_config = load_quality_gates(workspace.config)
    quality = apply_gates(
        GateInputs(
            config=workspace.config,
            catalog=workspace.catalog,
            metadata=workspace.metadata,
            fixtures=workspace.fixtures,
            findings=tuple(findings),
            test_summary=summary,
            conversions=conversions,
            load_failures=workspace.load_failures,
        ),
        gate_config,
    )

    bundle = ReportBundle(
        config=workspace.config,
        catalog=workspace.catalog,
        metadata=workspace.metadata,
        fixtures=workspace.fixtures,
        findings=tuple(findings),
        test_summary=summary,
        coverage=coverage_report,
        quality=quality,
        conversions=conversions,
        attack=workspace.attack,
        telemetry=load_telemetry_catalog(workspace.config),
        load_failures=workspace.load_failures,
        command=f"{CLI_NAME} validate",
    )

    if args.format == "json":
        console.write(render_json(bundle).rstrip("\n"), stream=stream)
        _write_reports(bundle, args, stream)
        return _validate_exit(bundle, args)

    _print_banners(stream)
    console.write(console.heading("Validation"), stream=stream)
    console.write(
        console.key_values(
            {
                "Project": workspace.config.project_name,
                "Profile": workspace.config.profile,
                "Rules": len(workspace.catalog),
                "Sidecars": len(workspace.metadata.sidecars),
                "Fixture cases": len(workspace.fixtures.cases),
                "Fixture sequences": len(workspace.fixtures.sequences),
                "Findings": len(findings),
            }
        ),
        stream=stream,
    )

    counts = _severity_counts(findings)
    if counts:
        console.blank(stream=stream)
        console.write("Findings by severity:", stream=stream)
        console.write(console.key_values(counts), stream=stream)

    if findings:
        console.blank(stream=stream)
        console.print_table(
            ["Severity", "Code", "Subject", "Message"],
            _finding_rows(findings, args.limit),
            stream=stream,
        )
        if len(findings) > args.limit:
            console.write(
                f"  ... {len(findings) - args.limit} more; raise --limit to see them",
                stream=stream,
            )

    if summary is not None:
        console.blank(stream=stream)
        console.write(
            f"Behavioral tests: {summary.passed} passed, {summary.failed} failed, "
            f"{summary.errored} errored, {summary.unsupported} unsupported, "
            f"{summary.skipped} skipped",
            stream=stream,
        )

    console.blank(stream=stream)
    console.write(console.subheading("Quality gates"), stream=stream)
    console.print_table(
        ["State", "Gate", "Detail"],
        [
            [
                "disabled" if not gate.enabled else ("pass" if gate.passed else "FAIL"),
                gate.gate,
                gate.detail,
            ]
            for gate in quality.gates
        ],
        stream=stream,
    )

    console.blank(stream=stream)
    console.write(
        console.status_line(bundle.passed, "overall result", stream=stream), stream=stream
    )
    _write_reports(bundle, args, stream)
    return _validate_exit(bundle, args)


def _validate_exit(bundle: ReportBundle, args: argparse.Namespace) -> int:
    """Decide the exit code, honouring ``--strict``.

    Without ``--strict`` only blocking findings and failing gates fail the run.
    With it, any finding at all does, which is the setting a release branch wants.
    """
    if not bundle.passed:
        return EXIT_FAILED
    if args.strict and bundle.findings:
        return EXIT_FAILED
    return EXIT_OK


def cmd_test(args: argparse.Namespace, stream: TextIO) -> int:
    """Run behavioral tests against the synthetic fixtures."""
    workspace = _open_workspace(args)
    summary = _run_tests(workspace, only=args.rule or None)

    bundle = ReportBundle(
        config=workspace.config,
        catalog=workspace.catalog,
        metadata=workspace.metadata,
        fixtures=workspace.fixtures,
        findings=tuple(workspace.binding_findings),
        test_summary=summary,
        load_failures=workspace.load_failures,
        command=f"{CLI_NAME} test",
    )

    if args.format == "json":
        console.write(render_json(bundle).rstrip("\n"), stream=stream)
        _write_reports(bundle, args, stream)
        return EXIT_OK if summary.successful else EXIT_FAILED

    console.write(console.banner(SYNTHETIC_TESTING_BANNER, stream=stream), stream=stream)
    console.write(console.heading("Behavioral testing"), stream=stream)
    console.write(
        console.key_values(
            {
                "Evaluator": summary.evaluator,
                "Total": summary.total,
                "Passed": summary.passed,
                "Failed": summary.failed,
                "Errored": summary.errored,
                "Unsupported": summary.unsupported,
                "Skipped": summary.skipped,
            }
        ),
        stream=stream,
    )

    problems = failing_results(summary)
    if problems:
        console.blank(stream=stream)
        console.print_table(
            ["Outcome", "Rule", "Case", "Expected", "Detail"],
            [
                [
                    str(result.outcome),
                    result.catalog_id,
                    result.case_id,
                    "match" if result.expected_match else "no match",
                    result.message,
                ]
                for result in problems[: args.limit]
            ],
            stream=stream,
        )
    elif args.verbose:
        console.blank(stream=stream)
        console.print_table(
            ["Outcome", "Rule", "Case"],
            [
                [str(result.outcome), result.catalog_id, result.case_id]
                for result in summary.results
            ],
            stream=stream,
        )

    console.blank(stream=stream)
    console.write(
        console.status_line(summary.successful, "behavioral test run", stream=stream),
        stream=stream,
    )
    _write_reports(bundle, args, stream)
    return EXIT_OK if summary.successful else EXIT_FAILED


def cmd_list_rules(args: argparse.Namespace, stream: TextIO) -> int:
    """List catalog rules, optionally filtered."""
    workspace = _open_workspace(args, load_fixture_data=False)

    criteria = RuleFilter(
        status=parse_status(args.status) if args.status else None,
        level=parse_severity(args.level) if args.level else None,
        product=args.product,
        category=args.category,
        service=args.service,
        technique=args.technique,
        tag=args.tag,
        correlation=args.correlation,
        text=args.search,
    )
    rules = workspace.catalog.filter(criteria)
    sidecars = workspace.metadata.by_catalog_id()

    if args.format == "json":
        payload = {
            "count": len(rules),
            "rules": [
                {
                    **rule.to_dict(),
                    "maturity": (
                        str(sidecars[rule.catalog_id].maturity)
                        if rule.catalog_id in sidecars
                        else None
                    ),
                }
                for rule in rules
            ],
        }
        console.write(_json_text(payload), stream=stream)
        return EXIT_OK

    if args.format == "csv":
        import csv
        from io import StringIO

        buffer = StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=[
                "catalog_id",
                "rule_id",
                "title",
                "level",
                "status",
                "maturity",
                "logsource",
                "correlation",
            ],
        )
        writer.writeheader()
        for rule in rules:
            writer.writerow(
                {
                    "catalog_id": rule.catalog_id,
                    "rule_id": rule.rule_id,
                    "title": rule.title,
                    "level": str(rule.level),
                    "status": str(rule.status),
                    "maturity": (
                        str(sidecars[rule.catalog_id].maturity)
                        if rule.catalog_id in sidecars
                        else ""
                    ),
                    "logsource": ("correlation" if rule.is_correlation else rule.logsource.key),
                    "correlation": str(rule.is_correlation),
                }
            )
        console.write(buffer.getvalue().rstrip(), stream=stream)
        return EXIT_OK

    console.print_table(
        ["Catalog ID", "Level", "Status", "Maturity", "Logsource", "Title"],
        [
            [
                rule.catalog_id,
                str(rule.level),
                str(rule.status),
                (str(sidecars[rule.catalog_id].maturity) if rule.catalog_id in sidecars else "-"),
                "correlation" if rule.is_correlation else rule.logsource.key,
                rule.title,
            ]
            for rule in rules
        ],
        stream=stream,
        empty_message="No rule matched the filter.",
    )
    console.blank(stream=stream)
    console.write(f"{len(rules)} of {len(workspace.catalog)} rule(s).", stream=stream)
    return EXIT_OK


def cmd_explain(args: argparse.Namespace, stream: TextIO) -> int:
    """Explain one rule: its metadata, condition, and fixture behaviour."""
    workspace = _open_workspace(args)
    query = args.rule or args.catalog_id or args.rule_id
    if not query:
        console.write(
            "Provide a catalog ID, UUID, or rule name (positional, --catalog-id, or --rule-id).",
            stream=stream,
        )
        return EXIT_USAGE
    rule = workspace.catalog.resolve(query)
    if rule is None:
        console.write(f"No rule matches {query!r}. Try '{CLI_NAME} list-rules'.", stream=stream)
        return EXIT_FAILED

    sidecar = workspace.metadata.get(rule.catalog_id)
    cases = workspace.fixtures.cases_for(rule.catalog_id)
    sequences = workspace.fixtures.sequences_for(rule.catalog_id)

    condition_text = ""
    if not rule.is_correlation:
        try:
            condition_text = parse_condition(rule.condition).render()
        except SdelError as exc:
            condition_text = f"(unsupported condition: {exc})"

    if args.format == "json":
        payload: dict[str, Any] = {
            "rule": rule.to_dict(),
            "parsed_condition": condition_text,
            "sidecar": sidecar.to_dict() if sidecar else None,
            "fixtures": workspace.fixtures.counts_for(rule.catalog_id),
            "banner": SYNTHETIC_DATA_BANNER,
        }
        console.write(_json_text(payload), stream=stream)
        return EXIT_OK

    console.write(console.heading(f"{rule.catalog_id}: {rule.title}"), stream=stream)
    console.write(
        console.key_values(
            {
                "UUID": rule.rule_id or "(none)",
                "File": rule.relative_path,
                "Status": str(rule.status),
                "Level": str(rule.level),
                "Author": rule.author,
                "Logsource": "correlation" if rule.is_correlation else rule.logsource.key,
                "Maturity": str(sidecar.maturity) if sidecar else "(no sidecar)",
            }
        ),
        stream=stream,
    )

    if rule.description:
        console.blank(stream=stream)
        console.write(console.subheading("Description"), stream=stream)
        console.write(f"  {rule.description}", stream=stream)

    if sidecar and sidecar.detection_hypothesis:
        console.blank(stream=stream)
        console.write(console.subheading("Detection hypothesis"), stream=stream)
        console.write(f"  {sidecar.detection_hypothesis}", stream=stream)

    if sidecar:
        console.blank(stream=stream)
        console.write(console.subheading("Telemetry"), stream=stream)
        console.write(console.bullet_list(sidecar.required_logs), stream=stream)
        if sidecar.required_fields:
            console.write("  Required fields:", stream=stream)
            console.write(
                console.bullet_list(sidecar.required_fields, indent="    "), stream=stream
            )

        console.blank(stream=stream)
        console.write(console.subheading("ATT&CK"), stream=stream)
        mapping = sidecar.attack_mapping
        if mapping.is_empty:
            reason = mapping.reason or "(none given)"
            console.write(f"  No mapping. Reason: {reason}", stream=stream)
        else:
            console.write(
                console.key_values(
                    {
                        "Techniques": ", ".join(mapping.techniques) or "-",
                        "Tactics": ", ".join(mapping.tactics) or "-",
                        "Detection strategies": ", ".join(mapping.detection_strategies) or "-",
                        "Analytics": ", ".join(mapping.analytics) or "-",
                        "Data components": ", ".join(mapping.data_components) or "-",
                    }
                ),
                stream=stream,
            )

    if rule.is_correlation and rule.correlation:
        console.blank(stream=stream)
        console.write(console.subheading("Correlation"), stream=stream)
        console.write(
            console.key_values({str(k): v for k, v in rule.correlation.items()}), stream=stream
        )
    elif condition_text:
        console.blank(stream=stream)
        console.write(console.subheading("Parsed condition"), stream=stream)
        console.write(f"  {condition_text}", stream=stream)

    console.blank(stream=stream)
    console.write(console.subheading("Fixture behaviour"), stream=stream)
    console.write(console.banner(SYNTHETIC_TESTING_BANNER, stream=stream), stream=stream)

    if not rule.is_correlation and cases:
        matcher = build_rule_matcher(rule, options=workspace.match_options)
        rows: list[list[str]] = []
        for case in cases:
            result = matcher.evaluate(case.event)
            expected = case.kind is FixtureKind.POSITIVE
            rows.append(
                [
                    "ok" if result.matched == expected else "MISMATCH",
                    case.kind.value,
                    case.case_id.rsplit("::", 1)[-1],
                    "match" if result.matched else "no match",
                    "; ".join(result.explanation[:2]),
                ]
            )
        console.print_table(["Verdict", "Kind", "Case", "Actual", "Why"], rows, stream=stream)
    elif sequences:
        console.print_table(
            ["Kind", "Sequence", "Events"],
            [
                [
                    sequence.kind.value,
                    sequence.sequence_id.rsplit("::", 1)[-1],
                    str(len(sequence.events)),
                ]
                for sequence in sequences
            ],
            stream=stream,
        )
    else:
        console.write("  No fixtures are registered for this rule.", stream=stream)

    return EXIT_OK


def cmd_coverage(args: argparse.Namespace, stream: TextIO) -> int:
    """Report authoring and testing coverage, and optionally a Navigator layer."""
    workspace = _open_workspace(args)
    summary = _run_tests(workspace) if args.tests else None
    report = build_coverage(workspace.catalog, workspace.metadata, workspace.fixtures, summary)

    if args.navigator:
        layer = build_layer(report, workspace.metadata, workspace.attack, catalog=workspace.catalog)
        write_layer(layer, Path(args.navigator))

    bundle = ReportBundle(
        config=workspace.config,
        catalog=workspace.catalog,
        metadata=workspace.metadata,
        fixtures=workspace.fixtures,
        findings=tuple(workspace.binding_findings),
        test_summary=summary,
        coverage=report,
        attack=workspace.attack,
        load_failures=workspace.load_failures,
        command=f"{CLI_NAME} coverage",
    )

    if args.format == "json":
        console.write(render_json(bundle).rstrip("\n"), stream=stream)
        _write_reports(bundle, args, stream)
        return EXIT_OK

    console.write(console.banner(COVERAGE_CAVEAT_BANNER, stream=stream), stream=stream)
    console.write(console.heading("Coverage"), stream=stream)
    console.write(
        console.key_values(
            {
                "Rules": report.total_rules,
                "With sidecar": report.rules_with_sidecar,
                "With ATT&CK mapping": report.rules_with_attack_mapping,
                "With fixtures": report.rules_with_fixtures,
                "Fully tested": report.rules_fully_tested,
                "Unique techniques": len(report.technique_counts),
                "Unique tactics": len(report.tactic_counts),
            }
        ),
        stream=stream,
    )
    console.blank(stream=stream)
    console.write(f"  {NO_EFFICACY_METRICS_NOTE}", stream=stream)

    if report.technique_counts:
        console.blank(stream=stream)
        console.write(console.subheading("Techniques addressed"), stream=stream)
        console.print_table(
            ["Technique", "Rules"],
            [[key, str(value)] for key, value in sorted(report.technique_counts.items())],
            stream=stream,
        )

    unverified = unverified_techniques(report, workspace.attack)
    if unverified:
        console.blank(stream=stream)
        console.write(
            "Techniques not present in the vendored ATT&CK catalog (omitted from any "
            "Navigator layer):",
            stream=stream,
        )
        console.write(console.bullet_list(unverified), stream=stream)

    gaps = technique_gaps(report, workspace.attack)
    if gaps:
        console.blank(stream=stream)
        console.write(console.subheading("Catalog techniques with no rule"), stream=stream)
        console.write(console.bullet_list(gaps), stream=stream)

    if report.untested_rules:
        console.blank(stream=stream)
        console.write(console.subheading("Rules without complete testing"), stream=stream)
        console.write(console.bullet_list(report.untested_rules), stream=stream)

    if args.navigator:
        console.blank(stream=stream)
        console.write(f"Navigator layer written to {args.navigator}", stream=stream)

    _write_reports(bundle, args, stream)
    return EXIT_OK


def cmd_convert(args: argparse.Namespace, stream: TextIO) -> int:
    """Convert rules to backend queries, offline, for demonstration only."""
    workspace = _open_workspace(args, load_fixture_data=False)
    conversion_config = load_conversion_config(workspace.config)
    conversions = convert_catalog(
        workspace.catalog,
        config=workspace.config,
        conversion_config=conversion_config,
        backend_keys=args.backend or None,
        only=args.rule or None,
    )

    if args.output:
        write_document(conversions.to_dict(), Path(args.output))

    if args.format == "json":
        console.write(_json_text(conversions.to_dict()), stream=stream)
        return EXIT_OK

    console.write(console.banner(CONVERSION_DEMONSTRATION_BANNER, stream=stream), stream=stream)
    console.write(console.heading("Conversion"), stream=stream)

    console.print_table(
        ["Backend", "Available", "Detail"],
        [
            [
                handle.key,
                "yes" if handle.available else "no",
                handle.error or f"{handle.settings.package} {handle.settings.version}",
            ]
            for handle in conversions.handles
        ],
        stream=stream,
        empty_message="No backends are configured.",
    )

    console.blank(stream=stream)
    console.write(console.key_values(conversions.counts()), stream=stream)

    for result in conversions.results:
        if result.status.value != "converted":
            continue
        console.blank(stream=stream)
        console.write(render_query_block(result), stream=stream)

    problems = [
        [str(result.status), result.catalog_id, result.backend, result.message]
        for result in conversions.results
        if result.status.value != "converted"
    ]
    if problems:
        console.blank(stream=stream)
        console.write(console.subheading("Not converted"), stream=stream)
        console.print_table(
            ["Status", "Rule", "Backend", "Detail"], problems[: args.limit], stream=stream
        )

    console.blank(stream=stream)
    console.write(f"  {NO_PRODUCTION_CLAIM}", stream=stream)
    if args.output:
        console.write(f"  Conversion record written to {args.output}", stream=stream)
    return EXIT_OK


def cmd_compare(args: argparse.Namespace, stream: TextIO) -> int:
    """Compare two saved JSON reports."""
    report = compare_files(Path(args.baseline), Path(args.current))

    if args.output:
        write_document(report.to_dict(), Path(args.output))

    if args.format == "json":
        console.write(_json_text(report.to_dict()), stream=stream)
        return EXIT_FAILED if (args.fail_on_regression and report.has_regressions) else EXIT_OK

    console.write(console.heading("Comparison"), stream=stream)
    console.write(
        console.key_values({"Baseline": report.baseline_label, "Current": report.current_label}),
        stream=stream,
    )

    console.blank(stream=stream)
    console.print_table(
        ["Direction", "Metric", "Baseline", "Current", "Delta"],
        [
            [
                str(change.direction),
                change.key,
                _number(change.baseline),
                _number(change.current),
                _number(change.delta),
            ]
            for change in report.metrics
            if change.direction.value != "unchanged" or args.verbose
        ],
        stream=stream,
        empty_message="No tracked metric changed.",
    )

    for change in report.sets:
        if not change.added and not change.removed:
            continue
        console.blank(stream=stream)
        console.write(console.subheading(change.key), stream=stream)
        if change.added:
            console.write("  Added:", stream=stream)
            console.write(console.bullet_list(change.added, indent="    "), stream=stream)
        if change.removed:
            console.write("  Removed:", stream=stream)
            console.write(console.bullet_list(change.removed, indent="    "), stream=stream)

    if report.gate_changes:
        console.blank(stream=stream)
        console.write(console.subheading("Gate changes"), stream=stream)
        console.print_table(
            ["Gate", "Baseline", "Current"],
            [[gate, before, after] for gate, before, after in report.gate_changes],
            stream=stream,
        )

    console.blank(stream=stream)
    console.write(
        console.status_line(
            not report.has_regressions,
            "no regressions" if not report.has_regressions else "regressions detected",
            stream=stream,
        ),
        stream=stream,
    )
    if args.output:
        console.write(f"  Comparison written to {args.output}", stream=stream)
    return EXIT_FAILED if (args.fail_on_regression and report.has_regressions) else EXIT_OK


DEMO_RULE = """\
title: 'Demonstration Process Launched From Synthetic Staging Path'
id: 6f1a2b3c-4d5e-4f60-9a71-2b3c4d5e6f70
status: experimental
description: >-
    Demonstration rule generated by the laboratory scaffold. Detects a process image
    executing from a synthetic staging directory that no managed installer writes to,
    which is the shape of behaviour a staging-and-execute sequence produces.
references:
    - 'https://attack.mitre.org/techniques/T1204/002/'
    - 'https://sigmahq.io/sigma-specification/'
author: 'Salvatore Mazzaglia'
date: 2026-08-01
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_staging_path:
        Image|startswith: 'C:\\\\Synthetic\\\\Staging\\\\'
    condition: selection_staging_path
falsepositives:
    - >-
        Packaging pipelines that build into the synthetic staging directory and run
        smoke tests from it before the artefact is signed.
    - >-
        Endpoint management agents that stage remediation binaries under the synthetic
        staging directory during a maintenance window.
level: medium
license: MIT
"""

DEMO_SIDECAR: dict[str, Any] = {
    "schema_version": "1.0.0",
    "catalog_id": "SDEL-DEMO-001",
    "sigma_rule_id": "6f1a2b3c-4d5e-4f60-9a71-2b3c4d5e6f70",
    "title": "Demonstration Process Launched From Synthetic Staging Path",
    "detection_hypothesis": (
        "If tooling is staged in a directory no managed installer writes to, the "
        "resulting process creation event shows an Image path rooted in that staging "
        "directory rather than in a managed installation directory."
    ),
    "platform": "windows",
    "rule_family": "windows",
    "maturity": "experimental",
    "required_logs": ["Windows process creation telemetry"],
    "required_channels": ["Microsoft-Windows-Sysmon/Operational"],
    "required_fields": ["Image"],
    "optional_fields": ["CommandLine", "ParentImage"],
    "attack_techniques": [{"id": "T1204.002", "name": "User Execution: Malicious File"}],
    "attack_tactics": [{"id": "TA0002", "name": "Execution"}],
    "attack_detection_strategies": [],
    "attack_analytics": [],
    "attack_data_components": [],
    "unmapped_defensive_objects_reason": (
        "No Detection Strategy, Analytic, or Data Component identifier for this "
        "technique was present in the pinned ATT&CK extraction used by this lab."
    ),
    "supported_backends": ["splunk", "elasticsearch-lucene"],
    "minimum_positive_tests": 2,
    "minimum_negative_tests": 3,
    "author": "Salvatore Mazzaglia",
    "license": "MIT",
    "synthetic_fixtures_only": True,
    "tuning_guidance": (
        "Prefer per-binary exclusions anchored on Image endswith. Do not exclude the "
        "whole staging directory, which would remove the rule's detection value."
    ),
}

DEMO_EVENTS: tuple[tuple[str, str, dict[str, Any], str], ...] = (
    (
        "positive",
        "case_01_staged_binary",
        {
            "Image": "C:\\Synthetic\\Staging\\synthetic_tool.exe",
            "CommandLine": "C:\\Synthetic\\Staging\\synthetic_tool.exe --synthetic-run",
            "ParentImage": "C:\\Synthetic\\Windows\\explorer.exe",
        },
        "Binary executed from the synthetic staging directory.",
    ),
    (
        "positive",
        "case_02_staged_script_host",
        {
            "Image": "C:\\Synthetic\\Staging\\nested\\synthetic_host.exe",
            "CommandLine": "synthetic_host.exe -File payload.txt",
            "ParentImage": "C:\\Synthetic\\Windows\\explorer.exe",
        },
        "Binary executed from a subdirectory of the staging directory.",
    ),
    (
        "negative",
        "case_01_managed_program_files",
        {
            "Image": "C:\\Synthetic\\Program Files\\SyntheticApp\\app.exe",
            "CommandLine": "app.exe --start",
            "ParentImage": "C:\\Synthetic\\Windows\\services.exe",
        },
        "Application executed from a managed installation directory.",
    ),
    (
        "negative",
        "case_02_system_directory",
        {
            "Image": "C:\\Synthetic\\Windows\\System32\\synthetic_utility.exe",
            "CommandLine": "synthetic_utility.exe /query",
            "ParentImage": "C:\\Synthetic\\Windows\\explorer.exe",
        },
        "System utility executed from the system directory.",
    ),
    (
        "negative",
        "case_03_similarly_named_path",
        {
            "Image": "C:\\Synthetic\\StagingArchive\\synthetic_tool.exe",
            "CommandLine": "synthetic_tool.exe --synthetic-run",
            "ParentImage": "C:\\Synthetic\\Windows\\explorer.exe",
        },
        "Binary executed from a managed directory with a similar name.",
    ),
)


def cmd_generate_demo(args: argparse.Namespace, stream: TextIO) -> int:
    """Write a complete, valid example: rule, sidecar, fixtures, and manifest.

    The example is written inside the project so it can be validated with the
    existing configuration, ATT&CK catalog, and telemetry catalog. A demo written
    somewhere else would need all of those copied alongside it to mean anything.
    """
    config = load_config(getattr(args, "root", None), profile=DEFAULT_PROFILE)
    root = Path(args.output)
    if not root.is_absolute():
        root = config.root / root
    root = root.resolve()

    try:
        root.relative_to(config.root)
    except ValueError:
        console.write(
            f"Refusing to write outside the project root {config.root}. The example must "
            "live inside the project so it can be validated against its configuration.",
            stream=stream,
        )
        return EXIT_FAILED

    catalog_id = DEMO_SIDECAR["catalog_id"]

    rule_path = root / "rules" / "windows" / "process_creation" / "demo_staging_path_execution.yml"
    sidecar_path = root / "metadata" / "rules" / f"{catalog_id}.json"
    fixture_dir = root / "fixtures" / "rules" / catalog_id

    targets = [rule_path, sidecar_path, fixture_dir / "manifest.json"]
    existing = [str(path) for path in targets if path.exists()]
    if existing and not args.force:
        console.write("Refusing to overwrite existing files:", stream=stream)
        console.write(console.bullet_list(existing), stream=stream)
        console.write("  Re-run with --force to replace them.", stream=stream)
        return EXIT_FAILED

    rule_path.parent.mkdir(parents=True, exist_ok=True)
    with rule_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(DEMO_RULE)

    sidecar_path.parent.mkdir(parents=True, exist_ok=True)
    with sidecar_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(DEMO_SIDECAR, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    base_time = datetime(2026, 8, 1, 9, 0, 0, tzinfo=UTC)
    manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "catalog_id": catalog_id,
        "sigma_rule_id": DEMO_SIDECAR["sigma_rule_id"],
        "rule_file": rule_path.relative_to(root).as_posix(),
        "rule_type": "standard",
        "synthetic": True,
        "logsource": {"category": "process_creation", "product": "windows"},
        "minimum_positive_cases": 2,
        "minimum_negative_cases": 3,
        "positive_cases": [],
        "negative_cases": [],
    }

    written: list[str] = [str(rule_path), str(sidecar_path)]
    for index, (kind, name, fields, scenario) in enumerate(DEMO_EVENTS):
        event = SyntheticEvent(
            event_id=f"{catalog_id}-{kind.upper()[:3]}-{index + 1:02d}",
            timestamp=base_time + timedelta(minutes=index),
            host="SYNTHETIC-HOST-01",
            user="SYNTHETIC-HOST-01\\synthetic-user",
            category="process_creation",
            product="windows",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            platform="windows",
            scenario=scenario,
            fields={"Computer": "SYNTHETIC-HOST-01", "EventID": 1, **fields},
        )
        relative = f"{kind}/{name}.jsonl"
        write_jsonl(fixture_dir / relative, [event])
        manifest[f"{kind}_cases"].append(
            {
                "name": name.split("_", 2)[-1],
                "file": relative,
                "expected": "match" if kind == "positive" else "no_match",
                "scenario": scenario,
            }
        )
        written.append(str(fixture_dir / relative))

    manifest_path = fixture_dir / "manifest.json"
    with manifest_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    written.append(str(manifest_path))

    console.write(console.banner(SYNTHETIC_DATA_BANNER, stream=stream), stream=stream)
    console.write(console.heading("Demonstration content generated"), stream=stream)
    console.write(console.bullet_list(written), stream=stream)

    base = root.relative_to(config.root).as_posix()
    console.blank(stream=stream)
    console.write("  Validate just this example with:", stream=stream)
    console.write(
        f"    {CLI_NAME} validate --rules {base}/rules --metadata {base}/metadata/rules "
        f"--fixtures {base}/fixtures",
        stream=stream,
    )
    return EXIT_OK


def cmd_version(args: argparse.Namespace, stream: TextIO) -> int:
    """Report tool, dependency, and vendored data versions."""
    status = pysigma_status()

    payload: dict[str, Any] = {
        "tool": CLI_NAME,
        "version": __version__,
        "python": sys.version.split()[0],
        "pysigma_available": status.available,
        "pysigma_version": status.version,
        "pysigma_error": status.error,
        "production_ready": False,
        "disclaimer": NO_PRODUCTION_CLAIM,
    }

    try:
        config = load_config(getattr(args, "root", None), profile=args.profile)
    except SdelError as exc:
        payload["config_error"] = str(exc)
    else:
        payload["project"] = config.project_name
        payload["profile"] = config.profile
        payload["upstream_versions"] = load_upstream_versions(config)
        attack = load_attack_catalog(config)
        payload["attack_version"] = attack.attack_version
        payload["attack_objects"] = attack.object_count

    if args.format == "json":
        console.write(_json_text(payload), stream=stream)
        return EXIT_OK

    console.write(console.heading(f"{CLI_NAME} {__version__}"), stream=stream)
    console.write(
        console.key_values(
            {
                key: ("yes" if value is True else "no" if value is False else value)
                for key, value in payload.items()
                if not isinstance(value, dict) and value is not None
            }
        ),
        stream=stream,
    )
    upstream = payload.get("upstream_versions")
    if isinstance(upstream, dict) and upstream:
        console.blank(stream=stream)
        console.write(console.subheading("Pinned upstream versions"), stream=stream)
        console.write(
            console.key_values({k: _flatten(v) for k, v in upstream.items()}), stream=stream
        )
    return EXIT_OK


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


def _number(value: float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return f"{value:.3f}"
    return str(int(value))


def _json_text(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, default=str)


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", help="Project root. Discovered from the CWD when omitted.")
    parser.add_argument(
        "--profile",
        default=DEFAULT_PROFILE,
        help=(
            "Config profile to load from config/<profile>.config.json "
            f"(default: {DEFAULT_PROFILE})."
        ),
    )
    parser.add_argument("--rules", help="Override the rules directory.")
    parser.add_argument("--metadata", help="Override the sidecar metadata directory.")
    parser.add_argument("--fixtures", help="Override the fixtures directory.")
    parser.add_argument(
        "--format",
        choices=("text", "table", "json", "csv"),
        default="text",
        help="Output format (default: text). 'table' is an alias for text.",
    )


def _add_report_outputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json-out", help="Write the full JSON report here.")
    parser.add_argument("--html-out", help="Write a standalone offline HTML report here.")
    parser.add_argument("--sarif-out", help="Write SARIF 2.1.0 quality findings here.")
    parser.add_argument("--junit-out", help="Write JUnit XML test results here.")
    parser.add_argument("--csv-out", help="Write findings as CSV here.")


def build_parser() -> argparse.ArgumentParser:
    """Build the full argument parser."""
    parser = argparse.ArgumentParser(
        prog=CLI_NAME,
        description=(
            "Offline Sigma detection-engineering laboratory. Authors, validates, tests, "
            "and documents original detection rules against synthetic telemetry. It never "
            "connects to a SIEM and never reads host logs."
        ),
        epilog=NO_PRODUCTION_CLAIM,
    )
    parser.add_argument("--version", action="version", version=f"{CLI_NAME} {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    validate = subparsers.add_parser(
        "validate", help="Validate the rule catalog and apply the quality gates."
    )
    _add_common(validate)
    _add_report_outputs(validate)
    validate.add_argument(
        "--strict", action="store_true", help="Fail on any finding, not just blocking ones."
    )
    validate.add_argument(
        "--skip-tests",
        action="store_true",
        help="Do not run behavioral tests. Gates that judge them become unproven and fail.",
    )
    validate.add_argument(
        "--skip-conversion",
        action="store_true",
        help="Do not attempt backend conversion. The conversion gate becomes unproven.",
    )
    validate.add_argument(
        "--no-pysigma", action="store_true", help="Skip pySigma parsing even if it is installed."
    )
    validate.add_argument(
        "--limit", type=int, default=50, help="Maximum findings to print (default: 50)."
    )
    validate.set_defaults(handler=cmd_validate)

    test = subparsers.add_parser("test", help="Run behavioral tests against synthetic fixtures.")
    _add_common(test)
    _add_report_outputs(test)
    test.add_argument("--rule", action="append", help="Limit to a catalog ID. Repeatable.")
    test.add_argument(
        "--verbose", action="store_true", help="List every result, not just failures."
    )
    test.add_argument(
        "--limit", type=int, default=50, help="Maximum failures to print (default: 50)."
    )
    test.set_defaults(handler=cmd_test)

    listing = subparsers.add_parser("list-rules", help="List catalog rules.")
    _add_common(listing)
    listing.add_argument("--status", help="Filter by Sigma status.")
    listing.add_argument("--level", help="Filter by severity level.")
    listing.add_argument("--product", help="Filter by logsource product.")
    listing.add_argument("--category", help="Filter by logsource category.")
    listing.add_argument("--service", help="Filter by logsource service.")
    listing.add_argument("--technique", help="Filter by ATT&CK technique tag.")
    listing.add_argument("--tag", help="Filter by an exact tag.")
    listing.add_argument("--search", help="Filter by free text in the title or description.")
    listing.add_argument(
        "--correlation",
        action="store_true",
        default=None,
        help="Show only correlation rules.",
    )
    listing.set_defaults(handler=cmd_list_rules)

    explain = subparsers.add_parser("explain", help="Explain one rule in detail.")
    _add_common(explain)
    explain.add_argument(
        "rule",
        nargs="?",
        default=None,
        help="Catalog ID, UUID, or rule name.",
    )
    explain.add_argument("--catalog-id", help="Catalog ID (alias for the positional rule).")
    explain.add_argument("--rule-id", help="Sigma UUID (alias for the positional rule).")
    explain.set_defaults(handler=cmd_explain)

    coverage = subparsers.add_parser("coverage", help="Report authoring and testing coverage.")
    _add_common(coverage)
    _add_report_outputs(coverage)
    coverage.add_argument(
        "--tests", action="store_true", help="Run behavioral tests to fill in tested counts."
    )
    coverage.add_argument("--navigator", help="Write an ATT&CK Navigator 4.5 layer here.")
    coverage.set_defaults(handler=cmd_coverage)

    convert = subparsers.add_parser(
        "convert", help="Convert rules to backend queries offline, for demonstration."
    )
    _add_common(convert)
    convert.add_argument("--backend", action="append", help="Limit to a backend key. Repeatable.")
    convert.add_argument("--rule", action="append", help="Limit to a catalog ID. Repeatable.")
    convert.add_argument("--output", help="Write the conversion record as JSON here.")
    convert.add_argument(
        "--limit", type=int, default=50, help="Maximum problems to print (default: 50)."
    )
    convert.set_defaults(handler=cmd_convert)

    compare = subparsers.add_parser("compare", help="Compare two saved JSON reports.")
    compare.add_argument("baseline", help="Path to the baseline JSON report.")
    compare.add_argument("current", help="Path to the current JSON report.")
    compare.add_argument(
        "--format", choices=("text", "json"), default="text", help="Output format."
    )
    compare.add_argument("--output", help="Write the comparison as JSON here.")
    compare.add_argument("--verbose", action="store_true", help="Include unchanged metrics.")
    compare.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit non-zero when a tracked metric regressed.",
    )
    compare.set_defaults(handler=cmd_compare)

    demo = subparsers.add_parser(
        "generate-demo", help="Write a complete example rule, sidecar, and fixtures."
    )
    demo.add_argument(
        "--output",
        default="examples/demo",
        help="Directory to write into (default: examples/demo).",
    )
    demo.add_argument("--force", action="store_true", help="Overwrite existing files.")
    demo.add_argument("--root", help="Project root. Discovered from the CWD when omitted.")
    demo.set_defaults(handler=cmd_generate_demo)

    version = subparsers.add_parser("version", help="Report tool and dependency versions.")
    version.add_argument("--root", help="Project root. Discovered from the CWD when omitted.")
    version.add_argument("--profile", default=DEFAULT_PROFILE, help="Config profile to load.")
    version.add_argument(
        "--format", choices=("text", "json"), default="text", help="Output format."
    )
    version.set_defaults(handler=cmd_version)

    return parser


def main(argv: Sequence[str] | None = None, *, stream: TextIO | None = None) -> int:
    """Entry point. Returns the process exit code rather than raising."""
    parser = build_parser()
    args = parser.parse_args(argv)
    target = stream or sys.stdout

    # Banners and rule text contain characters a legacy console code page cannot
    # encode. Reconfiguring is preferable to a UnicodeEncodeError mid-report.
    for handle in (sys.stdout, sys.stderr):
        reconfigure = getattr(handle, "reconfigure", None)
        if reconfigure is not None:
            with suppress(OSError, ValueError):
                reconfigure(encoding="utf-8", errors="replace")

    if getattr(args, "handler", None) is None:
        parser.print_help(target)
        return EXIT_USAGE

    try:
        return int(args.handler(args, target))
    except SdelError as exc:
        print(f"{CLI_NAME}: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print(f"{CLI_NAME}: interrupted", file=sys.stderr)
        return EXIT_REFUSED
    except OSError as exc:
        print(f"{CLI_NAME}: {exc}", file=sys.stderr)
        return EXIT_REFUSED


__all__ = [
    "EXIT_FAILED",
    "EXIT_OK",
    "EXIT_REFUSED",
    "EXIT_USAGE",
    "Workspace",
    "build_parser",
    "cmd_compare",
    "cmd_convert",
    "cmd_coverage",
    "cmd_explain",
    "cmd_generate_demo",
    "cmd_list_rules",
    "cmd_test",
    "cmd_validate",
    "cmd_version",
    "main",
]
