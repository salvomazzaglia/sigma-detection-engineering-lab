#!/usr/bin/env python3
"""Validate pinned upstream metadata and vendored ATT&CK identifiers offline."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    upstream = json.loads((ROOT / "config" / "upstream-versions.json").read_text(encoding="utf-8"))
    version = json.loads((ROOT / "data" / "attack" / "version.json").read_text(encoding="utf-8"))
    enterprise = json.loads(
        (ROOT / "data" / "attack" / "enterprise-attack-subset.json").read_text(encoding="utf-8")
    )
    print("upstream_sigma", upstream.get("sigma_specification", {}).get("version"))
    print("upstream_pysigma", upstream.get("pysigma", {}).get("version"))
    print("upstream_attack", upstream.get("mitre_attack", {}).get("enterprise_version"))
    print("vendored_attack", version)
    # Collect referenced technique IDs from metadata
    missing = []
    known = set()
    for obj in enterprise.get("objects") or enterprise.get("techniques") or []:
        if isinstance(obj, dict) and obj.get("id"):
            known.add(str(obj["id"]).upper())
    if not known and isinstance(enterprise, dict):
        for value in enterprise.values():
            if isinstance(value, list):
                for obj in value:
                    if isinstance(obj, dict) and obj.get("id"):
                        known.add(str(obj["id"]).upper())
            elif isinstance(value, dict) and value.get("id"):
                known.add(str(value["id"]).upper())
    meta_dir = ROOT / "metadata" / "rules"
    for path in sorted(meta_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for tech in data.get("attack_techniques") or []:
            tid = tech.get("id") if isinstance(tech, dict) else str(tech)
            if tid and str(tid).upper() not in known and known:
                missing.append((path.name, tid))
    if missing and known:
        print("MISSING", len(missing))
        for item in missing[:20]:
            print(" ", item)
        return 1
    print("offline_attack_id_check=ok")
    print("Never fetched remote ATT&CK data during this run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
