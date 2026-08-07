"""Standalone offline HTML report.

The document is entirely self-contained: inline CSS, no JavaScript, no CDN, no
web fonts, no external images. It opens correctly from a local file on a machine
with no network, which is the only way an offline laboratory's report can be
trusted to render what it says.

Collapsible sections use ``<details>``/``<summary>`` rather than script, so
interactivity survives with scripting disabled.

The four disclosure banners are rendered verbatim at the top of the document and
repeated in the footer. Every value that originates from rule or fixture content
is HTML-escaped and passed through redaction first.
"""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from sigma_detection_engineering_lab import __version__
from sigma_detection_engineering_lab.constants import (
    CONVERSION_DEMONSTRATION_BANNER,
    COVERAGE_CAVEAT_BANNER,
    NO_EFFICACY_METRICS_NOTE,
    NO_PRODUCTION_CLAIM,
    SYNTHETIC_DATA_BANNER,
    SYNTHETIC_TESTING_BANNER,
)
from sigma_detection_engineering_lab.json_report import ReportBundle, build_report
from sigma_detection_engineering_lab.severities import HTML_COLORS, Severity

STYLESHEET = """
:root {
  --bg: #f6f7f9;
  --panel: #ffffff;
  --ink: #1b1f24;
  --muted: #5a6b7c;
  --line: #d7dde3;
  --accent: #1f4e79;
  --warn-bg: #fff4d6;
  --warn-line: #d9a520;
  --pass: #2f7d4f;
  --fail: #a01b2b;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 0 0 4rem;
  background: var(--bg);
  color: var(--ink);
  font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
  font-size: 15px;
  line-height: 1.55;
}
.wrap { max-width: 1180px; margin: 0 auto; padding: 0 1.25rem; }
header.masthead {
  background: var(--accent);
  color: #fff;
  padding: 1.75rem 0 1.5rem;
  margin-bottom: 1.5rem;
}
header.masthead h1 { margin: 0 0 .35rem; font-size: 1.6rem; letter-spacing: .01em; }
header.masthead p { margin: 0; opacity: .9; font-size: .92rem; }
.banners { margin: 0 0 1.5rem; }
.banner {
  background: var(--warn-bg);
  border: 1px solid var(--warn-line);
  border-left-width: 6px;
  border-radius: 4px;
  padding: .7rem .9rem;
  margin-bottom: .55rem;
  font-weight: 600;
  font-size: .88rem;
  letter-spacing: .02em;
}
.banner.note { font-weight: 400; background: #eef3f8; border-color: #9db8d2; }
section { background: var(--panel); border: 1px solid var(--line); border-radius: 6px;
          padding: 1.1rem 1.25rem 1.35rem; margin-bottom: 1.35rem; }
section > h2 { margin: 0 0 .85rem; font-size: 1.12rem; color: var(--accent);
               border-bottom: 1px solid var(--line); padding-bottom: .45rem; }
h3 { font-size: .98rem; margin: 1.1rem 0 .5rem; }
.cards { display: flex; flex-wrap: wrap; gap: .75rem; margin-bottom: .5rem; }
.card { flex: 1 1 150px; border: 1px solid var(--line); border-radius: 5px;
        padding: .65rem .8rem; background: #fbfcfd; }
.card .label { display: block; font-size: .74rem; text-transform: uppercase;
               letter-spacing: .06em; color: var(--muted); }
.card .value { display: block; font-size: 1.4rem; font-weight: 600; margin-top: .15rem; }
table { width: 100%; border-collapse: collapse; margin-top: .4rem; font-size: .87rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--line);
         vertical-align: top; }
th { background: #eef1f4; font-weight: 600; font-size: .78rem;
     text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
tbody tr:nth-child(even) { background: #fafbfc; }
code, pre { font-family: "Cascadia Mono", Consolas, "SF Mono", Menlo, monospace; font-size: .84rem; }
pre { background: #1b1f24; color: #e6edf3; padding: .75rem .9rem; border-radius: 5px;
      overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
.pill { display: inline-block; padding: .1rem .5rem; border-radius: 10px; font-size: .74rem;
        font-weight: 600; color: #fff; letter-spacing: .03em; }
.verdict { font-size: 1rem; font-weight: 700; }
.verdict.pass { color: var(--pass); }
.verdict.fail { color: var(--fail); }
details { border: 1px solid var(--line); border-radius: 5px; margin-bottom: .5rem;
          background: #fbfcfd; }
summary { cursor: pointer; padding: .5rem .75rem; font-weight: 600; font-size: .88rem; }
details > div { padding: 0 .75rem .75rem; }
.muted { color: var(--muted); font-size: .84rem; }
footer.report-footer { border-top: 1px solid var(--line); margin-top: 2rem;
                       padding-top: 1rem; color: var(--muted); font-size: .82rem; }
@media print {
  body { background: #fff; }
  section { break-inside: avoid; border-color: #999; }
  .banner { border-color: #666; }
}
"""

GATE_SUCCESS_COLOR = "#2f7d4f"
GATE_FAIL_COLOR = "#a01b2b"
GATE_OFF_COLOR = "#5a6b7c"


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _pill(text: str, color: str) -> str:
    return f'<span class="pill" style="background:{_escape(color)}">{_escape(text)}</span>'


def _severity_pill(severity: str) -> str:
    try:
        color = HTML_COLORS[Severity(severity.lower())]
    except (ValueError, KeyError):
        color = GATE_OFF_COLOR
    return _pill(severity, color)


def _card(label: str, value: object) -> str:
    return (
        '<div class="card">'
        f'<span class="label">{_escape(label)}</span>'
        f'<span class="value">{_escape(value)}</span>'
        "</div>"
    )


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]], empty: str) -> str:
    """Build a table from pre-rendered cells. Cells must already be escaped."""
    if not rows:
        return f'<p class="muted">{_escape(empty)}</p>'
    head = "".join(f"<th>{_escape(header)}</th>" for header in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _banners_block() -> str:
    banners = [
        SYNTHETIC_DATA_BANNER,
        SYNTHETIC_TESTING_BANNER,
        CONVERSION_DEMONSTRATION_BANNER,
        COVERAGE_CAVEAT_BANNER,
    ]
    rendered = "".join(f'<div class="banner">{_escape(text)}</div>' for text in banners)
    rendered += f'<div class="banner note">{_escape(NO_PRODUCTION_CLAIM)}</div>'
    return f'<div class="banners">{rendered}</div>'


def _summary_section(document: Mapping[str, Any]) -> str:
    catalog = document.get("catalog", {})
    validation = document.get("validation", {})
    passed = bool(document.get("passed"))
    verdict = "PASS" if passed else "FAIL"
    verdict_class = "pass" if passed else "fail"

    cards = "".join(
        [
            _card("Rules", catalog.get("total", 0)),
            _card("Correlation", catalog.get("correlation", 0)),
            _card("Logsources", catalog.get("logsources", 0)),
            _card("Findings", len(validation.get("findings", []))),
            _card("Blocking", validation.get("error_count", 0)),
        ]
    )
    return (
        "<section><h2>Run summary</h2>"
        f'<p class="verdict {verdict_class}">Overall: {verdict}</p>'
        f'<div class="cards">{cards}</div>'
        f'<p class="muted">Generated {_escape(document.get("generated_at", ""))} '
        f"by sigma-detection-engineering-lab {_escape(__version__)} "
        f"(profile: {_escape(document.get('project', {}).get('profile', 'default'))}).</p>"
        "</section>"
    )


def _environment_section(document: Mapping[str, Any]) -> str:
    environment = document.get("environment", {})
    rows = [
        [_escape("Tool version"), _escape(environment.get("tool_version", ""))],
        [
            _escape("pySigma available"),
            _escape("yes" if environment.get("pysigma_available") else "no"),
        ],
        [_escape("pySigma version"), _escape(environment.get("pysigma_version") or "n/a")],
    ]
    if environment.get("pysigma_error"):
        rows.append([_escape("pySigma note"), _escape(environment["pysigma_error"])])
    attack = document.get("attack_catalog")
    if isinstance(attack, Mapping):
        rows.append([_escape("ATT&CK version"), _escape(attack.get("attack_version") or "unknown")])
        rows.append([_escape("ATT&CK objects"), _escape(attack.get("object_count", 0))])
    return (
        "<section><h2>Environment</h2>"
        + _table(["Property", "Value"], rows, "no environment data")
        + "</section>"
    )


def _findings_section(document: Mapping[str, Any]) -> str:
    validation = document.get("validation", {})
    findings: Sequence[Mapping[str, Any]] = validation.get("findings", [])
    rows = [
        [
            _severity_pill(str(finding.get("severity", "informational"))),
            _escape(finding.get("code", "")),
            _escape(finding.get("category", "")),
            _escape(finding.get("subject", "")),
            _escape(finding.get("message", "")),
            _escape(finding.get("remediation") or ""),
        ]
        for finding in findings
    ]
    counts = validation.get("counts_by_severity", {})
    cards = "".join(_card(name, value) for name, value in sorted(counts.items()))
    return (
        "<section><h2>Validation findings</h2>"
        + (f'<div class="cards">{cards}</div>' if cards else "")
        + _table(
            ["Severity", "Code", "Category", "Subject", "Message", "Remediation"],
            rows,
            "No validation findings were raised.",
        )
        + "</section>"
    )


def _tests_section(document: Mapping[str, Any]) -> str:
    tests = document.get("tests")
    if not isinstance(tests, Mapping):
        return ""
    totals = tests.get("totals", {})
    cards = "".join(
        _card(name.capitalize(), totals.get(name, 0))
        for name in ("total", "passed", "failed", "errored", "skipped", "unsupported")
    )
    interesting = [
        result for result in tests.get("results", []) if result.get("outcome") not in ("passed",)
    ]
    rows = [
        [
            _escape(result.get("outcome", "")),
            _escape(result.get("catalog_id", "")),
            _escape(result.get("case_id", "")),
            _escape("match" if result.get("expected_match") else "no match"),
            _escape(result.get("message", "")),
        ]
        for result in interesting
    ]
    return (
        "<section><h2>Behavioral testing</h2>"
        f'<div class="banner">{_escape(SYNTHETIC_TESTING_BANNER)}</div>'
        f'<p class="muted">Evaluator: {_escape(tests.get("evaluator", "unknown"))}. '
        "An unsupported result is never counted as a pass.</p>"
        f'<div class="cards">{cards}</div>'
        "<h3>Results needing attention</h3>"
        + _table(
            ["Outcome", "Rule", "Case", "Expected", "Detail"],
            rows,
            "Every executed case passed.",
        )
        + "</section>"
    )


def _coverage_section(document: Mapping[str, Any]) -> str:
    coverage = document.get("coverage")
    if not isinstance(coverage, Mapping):
        return ""
    cards = "".join(
        [
            _card("Rules", coverage.get("total_rules", 0)),
            _card("With sidecar", coverage.get("rules_with_sidecar", 0)),
            _card("ATT&CK mapped", coverage.get("rules_with_attack_mapping", 0)),
            _card("With fixtures", coverage.get("rules_with_fixtures", 0)),
            _card("Fully tested", coverage.get("rules_fully_tested", 0)),
            _card("Techniques", coverage.get("unique_techniques", 0)),
        ]
    )
    technique_rows = [
        [_escape(technique), _escape(count)]
        for technique, count in sorted(coverage.get("technique_counts", {}).items())
    ]
    logsource_rows = [
        [_escape(key), _escape(count)]
        for key, count in sorted(coverage.get("logsource_counts", {}).items())
    ]
    excluded = ", ".join(coverage.get("excluded_metrics", []))
    return (
        "<section><h2>Coverage</h2>"
        f'<div class="banner">{_escape(COVERAGE_CAVEAT_BANNER)}</div>'
        f'<div class="cards">{cards}</div>'
        f'<p class="muted">{_escape(NO_EFFICACY_METRICS_NOTE)} '
        f"Deliberately excluded: {_escape(excluded)}.</p>"
        "<details><summary>Techniques addressed</summary><div>"
        + _table(["Technique", "Rules"], technique_rows, "No techniques mapped.")
        + "</div></details>"
        "<details><summary>Logsource distribution</summary><div>"
        + _table(["Logsource", "Rules"], logsource_rows, "No logsources recorded.")
        + "</div></details>"
        "</section>"
    )


def _quality_section(document: Mapping[str, Any]) -> str:
    quality = document.get("quality")
    if not isinstance(quality, Mapping):
        return ""
    rows = []
    for gate in quality.get("gates", []):
        if not gate.get("enabled", True):
            state = _pill("disabled", GATE_OFF_COLOR)
        elif gate.get("passed"):
            state = _pill("pass", GATE_SUCCESS_COLOR)
        else:
            state = _pill("fail", GATE_FAIL_COLOR)
        rows.append(
            [
                state,
                _escape(gate.get("gate", "")),
                _escape(gate.get("detail", "")),
                _escape(gate.get("finding_count", 0)),
            ]
        )
    passed = bool(quality.get("passed"))
    return (
        "<section><h2>Quality gates</h2>"
        f'<p class="verdict {"pass" if passed else "fail"}">'
        f"{'All enabled gates passed' if passed else 'One or more gates failed'}</p>"
        + _table(["State", "Gate", "Detail", "Findings"], rows, "No gates were evaluated.")
        + "</section>"
    )


def _conversions_section(document: Mapping[str, Any]) -> str:
    conversions = document.get("conversions")
    if not isinstance(conversions, Mapping):
        return ""

    counts = conversions.get("counts", {})
    cards = "".join(
        _card(name.replace("_", " ").capitalize(), value)
        for name, value in sorted(counts.items())
        if value
    )

    blocks: list[str] = []
    for result in conversions.get("results", []):
        if result.get("status") != "converted":
            continue
        queries = "\n\n".join(result.get("queries", []))
        blocks.append(
            "<details><summary>"
            f"{_escape(result.get('catalog_id', ''))} &mdash; "
            f"{_escape(result.get('backend', ''))}"
            "</summary><div>"
            f'<div class="banner">{_escape(result.get("banner") or CONVERSION_DEMONSTRATION_BANNER)}</div>'
            f"<pre>{_escape(queries)}</pre>"
            f'<p class="muted">{_escape(result.get("message", ""))}</p>'
            "</div></details>"
        )

    problem_rows = [
        [
            _escape(result.get("status", "")),
            _escape(result.get("catalog_id", "")),
            _escape(result.get("backend", "")),
            _escape(result.get("message", "")),
        ]
        for result in conversions.get("results", [])
        if result.get("status") != "converted"
    ]

    return (
        "<section><h2>Backend conversions</h2>"
        f'<div class="banner">{_escape(CONVERSION_DEMONSTRATION_BANNER)}</div>'
        '<p class="muted">Queries below are demonstrations. They have not been validated '
        "against any schema, field mapping, index, or data model, and are not production "
        "ready.</p>"
        f'<div class="cards">{cards}</div>'
        + ("".join(blocks) if blocks else '<p class="muted">No queries were produced.</p>')
        + "<h3>Not converted</h3>"
        + _table(
            ["Status", "Rule", "Backend", "Detail"],
            problem_rows,
            "Every attempt produced a query.",
        )
        + "</section>"
    )


def _footer() -> str:
    banners = "".join(
        f"<li>{_escape(text)}</li>"
        for text in (
            SYNTHETIC_DATA_BANNER,
            SYNTHETIC_TESTING_BANNER,
            CONVERSION_DEMONSTRATION_BANNER,
            COVERAGE_CAVEAT_BANNER,
        )
    )
    return (
        '<footer class="report-footer">'
        f"<p>{_escape(NO_PRODUCTION_CLAIM)}</p>"
        f"<ul>{banners}</ul>"
        "<p>This report is generated offline. It contains no external resources, "
        "no scripts, and no network references.</p>"
        "</footer>"
    )


def render_html(bundle: ReportBundle, *, redact: bool = True) -> str:
    """Render the full standalone HTML document for a run."""
    document = build_report(bundle, redact=redact)
    title = f"{document.get('project', {}).get('name', 'detection lab')} report"

    body = "".join(
        [
            _banners_block(),
            _summary_section(document),
            _environment_section(document),
            _findings_section(document),
            _tests_section(document),
            _coverage_section(document),
            _quality_section(document),
            _conversions_section(document),
            _footer(),
        ]
    )

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="referrer" content="no-referrer">\n'
        '<meta name="robots" content="noindex">\n'
        f"<title>{_escape(title)}</title>\n"
        f"<style>{STYLESHEET}</style>\n"
        "</head>\n"
        "<body>\n"
        '<header class="masthead"><div class="wrap">'
        f"<h1>{_escape(title)}</h1>"
        f"<p>Offline Sigma detection-engineering laboratory &middot; version {_escape(__version__)}"
        f" &middot; generated {_escape(document.get('generated_at', ''))}</p>"
        "</div></header>\n"
        f'<main class="wrap">{body}</main>\n'
        "</body>\n"
        "</html>\n"
    )


def write_html(bundle: ReportBundle, destination: Path, *, redact: bool = True) -> Path:
    """Write the HTML report with LF line endings."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_html(bundle, redact=redact))
    return destination


__all__ = ["STYLESHEET", "render_html", "write_html"]
