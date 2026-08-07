"""Offline verification of the generated Sigma catalog, sidecars, and fixtures.

Checks structure, required metadata, taxonomy, synthetic-content safety, and the
relationship between rules, sidecars, and fixture directories.

Run:
    python tools/verify_catalog.py
"""

from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_RULE_KEYS = [
    "title",
    "id",
    "status",
    "description",
    "references",
    "author",
    "date",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "license",
]

REQUIRED_SIDECAR_KEYS = [
    "schema_version",
    "catalog_id",
    "sigma_rule_id",
    "title",
    "detection_hypothesis",
    "platform",
    "rule_family",
    "maturity",
    "required_logs",
    "required_channels",
    "required_fields",
    "optional_fields",
    "field_semantics",
    "collection_prerequisites",
    "retention_considerations",
    "expected_volume",
    "false_positive_strategy",
    "tuning_guidance",
    "test_strategy",
    "minimum_positive_tests",
    "minimum_negative_tests",
    "attack_techniques",
    "attack_tactics",
    "attack_detection_strategies",
    "attack_analytics",
    "attack_data_components",
    "unmapped_defensive_objects_reason",
    "supported_backends",
    "unsupported_backend_reasons",
    "related_rules",
    "author",
    "created_at",
    "modified_at",
    "version",
]

REQUIRED_EVENT_KEYS = [
    "schema_version",
    "event_id",
    "timestamp_utc",
    "synthetic",
    "platform",
    "logsource",
    "channel",
    "provider",
    "host",
    "user",
    "fields",
    "scenario",
    "notes",
]

BANNED_FALSE_POSITIVES = {"unknown", "legitimate activity", "administrator activity"}
UUID_BASE = "https://github.com/salvomazzaglia/sigma-detection-engineering-lab"

# Any IPv4 literal outside the documentation range 192.0.2.0/24 is rejected.
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ALLOWED_IP_PREFIX = "192.0.2."
DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|ru|cn|info|biz|xyz)\b")
ALLOWED_DOMAIN_SUFFIXES = (
    "attack.mitre.org",
    "learn.microsoft.com",
    "man7.org",
    "sigmahq.io",
    "github.com",
    "pypi.org",
)


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def check_text_safety(errors: list[str], label: str, text: str) -> None:
    for address in IPV4.findall(text):
        if not address.startswith(ALLOWED_IP_PREFIX):
            fail(errors, f"{label}: non-documentation IPv4 literal {address}")
    for domain in DOMAIN.findall(text):
        if not any(domain.lower().endswith(suffix) for suffix in ALLOWED_DOMAIN_SUFFIXES):
            fail(errors, f"{label}: unexpected public domain {domain}")


def pysigma_parse(errors: list[str]) -> str:
    """Parse every standard rule with pySigma when it is available offline."""
    try:
        from sigma.collection import SigmaCollection
    except ImportError:
        return "pySigma not installed, parse check skipped"

    standard = 0
    correlation = 0
    for path in sorted((ROOT / "rules").rglob("*.yml")):
        raw = path.read_text(encoding="utf-8")
        try:
            SigmaCollection.from_yaml(raw)
        except Exception as exc:  # noqa: BLE001 - surface any parser rejection
            fail(errors, f"{path.relative_to(ROOT).as_posix()}: pySigma rejected the rule: {exc}")
            continue
        if "\ncorrelation:" in raw:
            correlation += 1
        else:
            standard += 1
    return f"{standard} standard and {correlation} correlation rules parsed"


def main() -> int:
    errors: list[str] = []
    taxonomy = json.loads((ROOT / "config" / "allowed-taxonomy.json").read_text(encoding="utf-8"))
    attack_subset = json.loads(
        (ROOT / "data" / "attack" / "enterprise-attack-subset.json").read_text(encoding="utf-8")
    )
    known_techniques = {item["id"] for item in attack_subset["techniques"]}
    known_tactic_tags = set(taxonomy["allowed_tactic_tags"])

    rule_files = sorted((ROOT / "rules").rglob("*.yml"))
    sidecar_files = sorted((ROOT / "metadata" / "rules").glob("*.json"))

    seen_uuids: dict[str, str] = {}
    rule_ids: set[str] = set()
    documents = 0

    for path in rule_files:
        label = path.relative_to(ROOT).as_posix()
        raw = path.read_text(encoding="utf-8")
        check_text_safety(errors, label, raw)
        try:
            docs = [doc for doc in yaml.safe_load_all(raw) if doc]
        except yaml.YAMLError as exc:
            fail(errors, f"{label}: YAML parse error {exc}")
            continue
        documents += len(docs)
        for doc in docs:
            is_correlation = "correlation" in doc
            required = [key for key in REQUIRED_RULE_KEYS if key not in {"logsource", "detection"}]
            if not is_correlation:
                required = REQUIRED_RULE_KEYS
            for key in required:
                if key not in doc:
                    fail(errors, f"{label}: missing '{key}'")
            if doc.get("status") not in taxonomy["allowed_statuses"]:
                fail(errors, f"{label}: disallowed status {doc.get('status')!r}")
            if doc.get("level") not in taxonomy["allowed_levels"]:
                fail(errors, f"{label}: disallowed level {doc.get('level')!r}")
            if doc.get("author") != "Salvatore Mazzaglia":
                fail(errors, f"{label}: unexpected author {doc.get('author')!r}")
            if doc.get("license") != "MIT":
                fail(errors, f"{label}: unexpected license {doc.get('license')!r}")
            if str(doc.get("date")) != "2026-08-01":
                fail(errors, f"{label}: unexpected date {doc.get('date')!r}")
            if not doc.get("references"):
                fail(errors, f"{label}: empty references")
            if not any("attack.mitre.org" in ref for ref in doc.get("references", [])):
                fail(errors, f"{label}: no authoritative ATT&CK reference")
            for entry in doc.get("falsepositives", []):
                if entry.strip().lower() in BANNED_FALSE_POSITIVES:
                    fail(errors, f"{label}: non-specific false positive {entry!r}")
                if len(entry) < 60:
                    fail(errors, f"{label}: false positive lacks detail: {entry!r}")
            for tag in doc.get("tags", []):
                if tag.startswith("attack.t"):
                    technique = tag.split(".", 1)[1].upper()
                    if technique not in known_techniques:
                        fail(errors, f"{label}: unverified technique tag {tag}")
                elif tag not in known_tactic_tags:
                    fail(errors, f"{label}: unknown tactic tag {tag}")
            identifier = str(doc.get("id"))
            try:
                uuid.UUID(identifier)
            except ValueError:
                fail(errors, f"{label}: invalid UUID {identifier!r}")
            if identifier in seen_uuids:
                fail(errors, f"{label}: duplicate UUID also used by {seen_uuids[identifier]}")
            seen_uuids[identifier] = label
            rule_ids.add(identifier)

            if is_correlation:
                correlation = doc["correlation"]
                if correlation["type"] not in taxonomy["allowed_correlation_types"]:
                    fail(errors, f"{label}: unsupported correlation type {correlation['type']}")
                if not correlation.get("rules"):
                    fail(errors, f"{label}: correlation without base rules")
            else:
                detection = doc.get("detection", {})
                condition = detection.get("condition", "")
                if not condition:
                    fail(errors, f"{label}: missing condition")
                if "1 of them" in condition or "all of them" in condition:
                    fail(errors, f"{label}: condition uses a discouraged wildcard form")
                names = [key for key in detection if key != "condition"]
                for name in names:
                    if name not in condition:
                        fail(errors, f"{label}: selection '{name}' unused by the condition")
                logsource = doc.get("logsource", {})
                if logsource.get("product") not in taxonomy["allowed_products"]:
                    fail(errors, f"{label}: unknown logsource product")
                if "category" in logsource and logsource["category"] not in taxonomy["allowed_categories"]:
                    fail(errors, f"{label}: unknown logsource category")
                if "service" in logsource and logsource["service"] not in taxonomy["allowed_services"]:
                    fail(errors, f"{label}: unknown logsource service")

    catalog_ids: set[str] = set()
    for path in sidecar_files:
        label = path.relative_to(ROOT).as_posix()
        sidecar = json.loads(path.read_text(encoding="utf-8"))
        check_text_safety(errors, label, path.read_text(encoding="utf-8"))
        for key in REQUIRED_SIDECAR_KEYS:
            if key not in sidecar:
                fail(errors, f"{label}: missing sidecar field '{key}'")
        catalog_id = sidecar["catalog_id"]
        catalog_ids.add(catalog_id)
        if path.stem != catalog_id:
            fail(errors, f"{label}: filename does not match catalog id")
        expected = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{UUID_BASE}/{catalog_id}"))
        if sidecar["sigma_rule_id"] != expected:
            fail(errors, f"{label}: sigma_rule_id is not the derived uuid5 value")
        if sidecar["sigma_rule_id"] not in rule_ids:
            fail(errors, f"{label}: sigma_rule_id has no matching rule document")
        if sidecar["maturity"] not in taxonomy["allowed_maturity"]:
            fail(errors, f"{label}: disallowed maturity {sidecar['maturity']!r}")
        if not sidecar["detection_hypothesis"]:
            fail(errors, f"{label}: empty detection hypothesis")
        if not sidecar["required_logs"] or not sidecar["required_fields"]:
            fail(errors, f"{label}: empty telemetry requirements")
        has_mapping = bool(
            sidecar["attack_detection_strategies"]
            or sidecar["attack_analytics"]
            or sidecar["attack_data_components"]
        )
        if not has_mapping and not sidecar["unmapped_defensive_objects_reason"]:
            fail(errors, f"{label}: no defensive mapping and no unmapped reason")
        for technique in sidecar["attack_techniques"]:
            if technique["id"] not in known_techniques:
                fail(errors, f"{label}: unverified technique {technique['id']}")

    if catalog_ids != {path.stem for path in sidecar_files}:
        fail(errors, "sidecar catalog ids do not match sidecar filenames")

    fixture_events = 0
    standard_dirs = sorted((ROOT / "fixtures" / "rules").iterdir())
    correlation_dirs = sorted((ROOT / "fixtures" / "correlation").iterdir())

    for directory in standard_dirs + correlation_dirs:
        label = directory.relative_to(ROOT).as_posix()
        is_correlation = directory.parent.name == "correlation"
        if directory.name not in catalog_ids:
            fail(errors, f"{label}: fixture directory has no sidecar")
        manifest_path = directory / "manifest.json"
        if not manifest_path.exists():
            fail(errors, f"{label}: missing manifest.json")
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("synthetic") is not True:
            fail(errors, f"{label}: manifest is not marked synthetic")
        positives = sorted((directory / "positive").glob("*.jsonl"))
        negatives = sorted((directory / "negative").glob("*.jsonl"))
        min_pos, min_neg = (2, 2) if is_correlation else (2, 3)
        if len(positives) < min_pos:
            fail(errors, f"{label}: {len(positives)} positive files, expected at least {min_pos}")
        if len(negatives) < min_neg:
            fail(errors, f"{label}: {len(negatives)} negative files, expected at least {min_neg}")
        for fixture in positives + negatives:
            text = fixture.read_text(encoding="utf-8")
            check_text_safety(errors, fixture.relative_to(ROOT).as_posix(), text)
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                fixture_events += 1
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    fail(errors, f"{fixture.name}:{line_number}: invalid JSON {exc}")
                    continue
                for key in REQUIRED_EVENT_KEYS:
                    if key not in event:
                        fail(errors, f"{fixture.name}:{line_number}: missing event field '{key}'")
                if event.get("synthetic") is not True:
                    fail(errors, f"{fixture.name}:{line_number}: event not marked synthetic")

    pysigma_status = pysigma_parse(errors)

    print("=" * 72)
    print("catalog verification")
    print("=" * 72)
    print(f"pysigma                   : {pysigma_status}")
    print(f"rule files                : {len(rule_files)}")
    print(f"yaml documents            : {documents}")
    print(f"sidecars                  : {len(sidecar_files)}")
    print(f"standard fixture packs    : {len(standard_dirs)}")
    print(f"correlation fixture packs : {len(correlation_dirs)}")
    print(f"fixture events            : {fixture_events}")
    print(f"unique rule uuids         : {len(seen_uuids)}")
    if errors:
        print("-" * 72)
        print(f"ERRORS: {len(errors)}")
        for message in errors[:60]:
            print(f"  - {message}")
        return 1
    print("-" * 72)
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
