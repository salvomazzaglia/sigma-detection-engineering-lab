#!/usr/bin/env python3
"""Generate deterministic sample reports under examples/ (synthetic only)."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
EXAMPLES = ROOT / "examples"


def run(args: list[str]) -> None:
    print("+", " ".join(args))
    subprocess.run(args, cwd=ROOT, check=True)


def write_catalog_csv() -> None:
    from sigma_detection_engineering_lab.config import load_config
    from sigma_detection_engineering_lab.metadata_loader import assign_catalog_ids, load_metadata
    from sigma_detection_engineering_lab.rule_loader import load_rules

    cfg = load_config()
    outcome = load_rules(cfg)
    meta = load_metadata(cfg)
    rules, _findings = assign_catalog_ids(outcome.rules, meta)
    rows = []
    for rule in rules:
        rows.append(
            {
                "catalog_id": rule.catalog_id,
                "sigma_id": rule.rule_id,
                "title": rule.title,
                "level": str(rule.level),
                "status": str(rule.status),
                "platform": rule.logsource.product or "",
                "correlation": str(rule.is_correlation),
            }
        )
    path = EXAMPLES / "sample-rule-catalog.csv"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "catalog_id",
                "sigma_id",
                "title",
                "level",
                "status",
                "platform",
                "correlation",
            ],
        )
        writer.writeheader()
        for row in sorted(rows, key=lambda item: item["catalog_id"]):
            for key, value in list(row.items()):
                text = str(value)
                if text[:1] in {"=", "+", "-", "@"}:
                    row[key] = "'" + text
            writer.writerow(row)


def expand_conversions(backend: str, folder: Path) -> None:
    payload_path = folder / "conversions.json"
    if not payload_path.is_file():
        return
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    results = payload
    if isinstance(payload, dict):
        results = payload.get("results") or payload.get("conversions") or payload.get("items") or []
    for item in results:
        if not isinstance(item, dict):
            continue
        catalog_id = str(item.get("catalog_id") or item.get("rule") or "unknown")
        queries = list(item.get("queries") or [])
        if item.get("query") and not queries:
            queries = [item["query"]]
        status = str(item.get("status") or ("converted" if queries else "unsupported"))
        parts = [
            "DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION REQUIRED",
            f"backend={backend}",
            f"catalog_id={catalog_id}",
            f"status={status}",
            "",
        ]
        for query in queries:
            parts.append(str(query))
            parts.append("")
        if item.get("error"):
            parts.append(f"error={item['error']}")
        suffix = "spl" if backend == "splunk" else "lucene.txt"
        (folder / f"{catalog_id}.{suffix}").write_text(
            "\n".join(parts), encoding="utf-8", newline="\n"
        )


def main() -> int:
    EXAMPLES.mkdir(parents=True, exist_ok=True)
    splunk = EXAMPLES / "sample-conversions" / "splunk"
    elastic = EXAMPLES / "sample-conversions" / "elasticsearch"
    splunk.mkdir(parents=True, exist_ok=True)
    elastic.mkdir(parents=True, exist_ok=True)

    run(
        [
            PY,
            "-m",
            "sigma_detection_engineering_lab",
            "validate",
            "--rules",
            "rules",
            "--metadata",
            "metadata/rules",
            "--strict",
            "--json-out",
            str(EXAMPLES / "sample-quality-report.json"),
            "--html-out",
            str(EXAMPLES / "sample-quality-report.html"),
            "--sarif-out",
            str(EXAMPLES / "sample-quality-report.sarif"),
            "--junit-out",
            str(EXAMPLES / "sample-test-results.xml"),
        ]
    )
    run(
        [
            PY,
            "-m",
            "sigma_detection_engineering_lab",
            "coverage",
            "--tests",
            "--json-out",
            str(EXAMPLES / "sample-coverage-report.json"),
            "--html-out",
            str(EXAMPLES / "sample-coverage-report.html"),
            "--navigator",
            str(EXAMPLES / "attack-navigator-layer.json"),
        ]
    )
    run(
        [
            PY,
            "-m",
            "sigma_detection_engineering_lab",
            "convert",
            "--backend",
            "splunk",
            "--output",
            str(splunk / "conversions.json"),
        ]
    )
    run(
        [
            PY,
            "-m",
            "sigma_detection_engineering_lab",
            "convert",
            "--backend",
            "elasticsearch-lucene",
            "--output",
            str(elastic / "conversions.json"),
        ]
    )

    expand_conversions("splunk", splunk)
    expand_conversions("elasticsearch-lucene", elastic)
    write_catalog_csv()

    # Preserve the curated examples/README.md; only refresh the conversions note.
    conversions_readme = EXAMPLES / "sample-conversions" / "README.md"
    if not conversions_readme.exists():
        conversions_readme.write_text(
            """# Sample conversions

DEMONSTRATION CONVERSION — ENVIRONMENT-SPECIFIC VALIDATION REQUIRED

Offline pySigma backend conversions only. Not production-ready.
""",
            encoding="utf-8",
            newline="\n",
        )

    for path in (
        EXAMPLES / "README.md",
        EXAMPLES / "sample-quality-report.html",
        EXAMPLES / "sample-quality-report.json",
        EXAMPLES / "sample-coverage-report.html",
    ):
        text = path.read_text(encoding="utf-8")
        if "SYNTHETIC" not in text.upper():
            raise SystemExit(f"Missing synthetic marker in {path}")

    print("Sample reports generated under examples/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
