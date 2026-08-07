#!/usr/bin/env python3
"""Compare local catalog UUIDs/titles against a local SigmaHQ/sigma checkout."""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULE_ID_RE = re.compile(
    r"(?im)^id:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s*$"
)
TITLE_RE = re.compile(r"(?im)^title:\s*(.+?)\s*$")


def load_local_rows() -> list[dict[str, str]]:
    export = ROOT / "temp" / "rule_ids_titles.json"
    if export.exists():
        return json.loads(export.read_text(encoding="utf-8"))
    rows: list[dict[str, str]] = []
    for path in sorted((ROOT / "rules").rglob("*.yml")):
        text = path.read_text(encoding="utf-8")
        rid = RULE_ID_RE.search(text)
        title = TITLE_RE.search(text)
        if not rid or not title:
            raise SystemExit(f"missing id/title in {path}")
        rows.append(
            {
                "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                "id": rid.group(1).lower(),
                "title": title.group(1).strip().strip("'\""),
            }
        )
    return rows


def index_upstream(sigma_root: Path) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    by_id: dict[str, list[str]] = {}
    by_title: dict[str, list[str]] = {}
    for path in sigma_root.rglob("*.yml"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rid = RULE_ID_RE.search(text)
        title = TITLE_RE.search(text)
        rel = str(path.relative_to(sigma_root)).replace("\\", "/")
        if rid:
            by_id.setdefault(rid.group(1).lower(), []).append(rel)
        if title:
            by_title.setdefault(title.group(1).strip().strip("'\"").casefold(), []).append(rel)
    return by_id, by_title


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: offline_sigmahq_originality.py <path-to-SigmaHQ/sigma>")
        return 2
    sigma_root = Path(sys.argv[1]).resolve()
    if not sigma_root.exists():
        raise SystemExit(f"missing upstream path: {sigma_root}")

    rows = load_local_rows()
    local_ids = [r["id"] for r in rows]
    local_titles = [r["title"] for r in rows]
    if len(set(local_ids)) != len(local_ids):
        raise SystemExit("duplicate local UUIDs")
    if len(set(t.casefold() for t in local_titles)) != len(local_titles):
        raise SystemExit("duplicate local titles")

    by_id, by_title = index_upstream(sigma_root)
    uuid_hits = []
    title_hits = []
    for row in rows:
        if row["id"] in by_id:
            uuid_hits.append({**row, "upstream_paths": by_id[row["id"]]})
        key = row["title"].casefold()
        if key in by_title:
            title_hits.append({**row, "upstream_paths": by_title[key]})

    result = {
        "method": "offline full-text index of SigmaHQ/sigma YAML rules",
        "upstream_path": str(sigma_root),
        "checked_rules": len(rows),
        "upstream_rule_files_indexed": sum(len(v) for v in by_id.values()),
        "upstream_unique_ids": len(by_id),
        "upstream_unique_titles": len(by_title),
        "local_uuid_unique": True,
        "local_title_unique": True,
        "uuid_collisions": uuid_hits,
        "title_exact_collisions": title_hits,
        "local_title_frequency": Counter(t.casefold() for t in local_titles).most_common(5),
    }
    out = ROOT / "temp" / "originality_offline_result.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("WROTE", out)
    print("CHECKED", len(rows))
    print("UPSTREAM_IDS", len(by_id))
    print("UUID_COLLISIONS", len(uuid_hits))
    print("TITLE_COLLISIONS", len(title_hits))
    return 0 if not uuid_hits and not title_hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
