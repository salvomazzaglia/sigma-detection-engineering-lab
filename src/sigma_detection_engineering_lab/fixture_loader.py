"""Loading synthetic fixtures from JSONL files and per-rule manifests.

The project layout keys fixtures on the catalog identifier, with one manifest per
rule declaring what each file is meant to prove::

    fixtures/
      rules/<catalog_id>/manifest.json
      rules/<catalog_id>/positive/case_NN_*.jsonl        one event per case
      rules/<catalog_id>/negative/case_NN_*.jsonl
      correlation/<catalog_id>/manifest.json
      correlation/<catalog_id>/positive/sequence_NN_*.jsonl   one sequence per file
      correlation/<catalog_id>/negative/sequence_NN_*.jsonl

Naming a case in its manifest rather than inferring intent from a filename means
a fixture that is silently dropped, misfiled, or renamed shows up as an error
instead of quietly reducing coverage.

Two older layouts still load: a single top-level ``manifest.json`` listing files
explicitly, and directory-convention discovery. They are tried only when the
per-rule layout is absent.

Every path is resolved inside the project root, every file is size-bounded, and
every record must declare itself synthetic. ``fixtures/malformed`` is skipped by
default: those files exist to prove the loader rejects them, so counting them as
catalog fixtures would invert their purpose.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.constants import SYNTHETIC_DATA_BANNER
from sigma_detection_engineering_lab.errors import FixtureError, PathSafetyError
from sigma_detection_engineering_lab.event_model import EventModelError, SyntheticEvent
from sigma_detection_engineering_lab.models import (
    CorrelationSequence,
    FixtureCase,
    FixtureKind,
)
from sigma_detection_engineering_lab.paths import (
    relative_display,
    safe_read_text,
    safe_resolve,
)

MANIFEST_NAME: Final[str] = "manifest.json"
POSITIVE_FILE: Final[str] = "positive.jsonl"
NEGATIVE_FILE: Final[str] = "negative.jsonl"
SEQUENCES_DIRECTORY: Final[str] = "sequences"
RULES_SUBDIRECTORY: Final[str] = "rules"
CORRELATION_SUBDIRECTORY: Final[str] = "correlation"
EXCLUDED_DIRECTORIES: Final[frozenset[str]] = frozenset({"malformed", "invalid", "_disabled"})

CASE_SECTIONS: Final[tuple[tuple[str, FixtureKind], ...]] = (
    ("positive_cases", FixtureKind.POSITIVE),
    ("negative_cases", FixtureKind.NEGATIVE),
)
SEQUENCE_SECTIONS: Final[tuple[tuple[str, FixtureKind], ...]] = (
    ("positive_sequences", FixtureKind.POSITIVE),
    ("negative_sequences", FixtureKind.NEGATIVE),
)


def _parse_kind(value: object, source: str) -> FixtureKind:
    text = str(value).strip().lower()
    try:
        return FixtureKind(text)
    except ValueError as exc:
        raise FixtureError(
            f"{source}: fixture kind must be 'positive' or 'negative', got {value!r}"
        ) from exc


def load_jsonl_events(
    path: Path,
    *,
    config: LabConfig,
    max_events: int | None = None,
) -> list[SyntheticEvent]:
    """Read a JSONL file into synthetic events.

    Blank lines are ignored. Every other line must be a complete JSON object.

    Raises:
        FixtureError: on unreadable files, malformed JSON, non-object records,
            events that fail validation, or a record count over the limit.
    """
    relative = relative_display(config.root, path)
    limit = max_events if max_events is not None else config.limits.max_events_per_fixture

    try:
        text = safe_read_text(path, max_bytes=config.limits.max_file_bytes)
    except PathSafetyError as exc:
        raise FixtureError(f"{relative}: {exc}") from exc

    if "\x00" in text:
        raise FixtureError(f"{relative}: NUL byte in fixture file is rejected")

    events: list[SyntheticEvent] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if len(events) >= limit:
            raise FixtureError(
                f"{relative}: more than {limit} events; raise 'max_events_per_fixture' "
                "only with a deliberate reason"
            )
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise FixtureError(f"{relative}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(record, dict):
            raise FixtureError(
                f"{relative}:{number}: each line must be a JSON object, got {type(record).__name__}"
            )
        try:
            events.append(SyntheticEvent.from_mapping(record, label=f"{relative}:{number}"))
        except EventModelError as exc:
            raise FixtureError(str(exc)) from exc
    return events


@dataclass(frozen=True)
class FixtureSet:
    """Every fixture available to the behavioral test runner."""

    cases: tuple[FixtureCase, ...] = ()
    sequences: tuple[CorrelationSequence, ...] = ()
    errors: tuple[tuple[str, str], ...] = ()
    banner: str = SYNTHETIC_DATA_BANNER
    manifest_used: bool = False

    def cases_for(
        self,
        catalog_id: str,
        kind: FixtureKind | None = None,
    ) -> tuple[FixtureCase, ...]:
        """Return the event fixtures registered for a rule."""
        return tuple(
            case
            for case in self.cases
            if case.catalog_id == catalog_id and (kind is None or case.kind is kind)
        )

    def sequences_for(
        self,
        catalog_id: str,
        kind: FixtureKind | None = None,
    ) -> tuple[CorrelationSequence, ...]:
        """Return the correlation sequences registered for a rule."""
        return tuple(
            sequence
            for sequence in self.sequences
            if sequence.catalog_id == catalog_id and (kind is None or sequence.kind is kind)
        )

    def covered_catalog_ids(self) -> frozenset[str]:
        """Return every rule identifier that has at least one fixture."""
        return frozenset(
            [case.catalog_id for case in self.cases]
            + [sequence.catalog_id for sequence in self.sequences]
        )

    def counts_for(self, catalog_id: str) -> dict[str, int]:
        """Return positive/negative counts for a rule, used by quality gates."""
        return {
            "positive_events": len(self.cases_for(catalog_id, FixtureKind.POSITIVE)),
            "negative_events": len(self.cases_for(catalog_id, FixtureKind.NEGATIVE)),
            "positive_sequences": len(self.sequences_for(catalog_id, FixtureKind.POSITIVE)),
            "negative_sequences": len(self.sequences_for(catalog_id, FixtureKind.NEGATIVE)),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "banner": self.banner,
            "manifest_used": self.manifest_used,
            "case_count": len(self.cases),
            "sequence_count": len(self.sequences),
            "error_count": len(self.errors),
            "errors": [{"path": path, "message": message} for path, message in self.errors],
        }


def _build_cases(
    events: Iterable[SyntheticEvent],
    *,
    catalog_id: str,
    kind: FixtureKind,
    source: str,
    description: str = "",
) -> list[FixtureCase]:
    return [
        FixtureCase(
            case_id=f"{catalog_id}::{kind.value}::{event.event_id}",
            catalog_id=catalog_id,
            kind=kind,
            event=event,
            description=description,
            source_path=source,
        )
        for event in events
    ]


def _build_sequence(
    events: Sequence[SyntheticEvent],
    *,
    catalog_id: str,
    kind: FixtureKind,
    sequence_id: str,
    source: str,
    description: str = "",
    limit: int,
) -> CorrelationSequence:
    if len(events) > limit:
        raise FixtureError(
            f"{source}: sequence holds {len(events)} events, exceeding the limit {limit}"
        )
    if not events:
        raise FixtureError(f"{source}: correlation sequence is empty")
    return CorrelationSequence(
        sequence_id=sequence_id,
        catalog_id=catalog_id,
        kind=kind,
        events=tuple(sorted(events, key=lambda event: (event.timestamp, event.event_id))),
        description=description,
        source_path=source,
    )


def _sequence_kind_from_name(name: str) -> FixtureKind | None:
    lowered = name.lower()
    if "negative" in lowered:
        return FixtureKind.NEGATIVE
    if "positive" in lowered:
        return FixtureKind.POSITIVE
    return None


def _read_manifest(manifest_path: Path, *, config: LabConfig) -> tuple[Mapping[str, Any], str]:
    """Read and decode a manifest, returning it with its display path."""
    relative = relative_display(config.root, manifest_path)
    try:
        text = safe_read_text(manifest_path, max_bytes=config.limits.max_file_bytes)
        data = json.loads(text)
    except PathSafetyError as exc:
        raise FixtureError(f"{relative}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FixtureError(f"{relative}: invalid JSON: {exc}") from exc
    if not isinstance(data, Mapping):
        raise FixtureError(f"{relative}: manifest root must be an object")
    return data, relative


def _resolve_entry_file(
    entry: Mapping[str, Any],
    base: Path,
    label: str,
    config: LabConfig,
) -> Path:
    file_ref = str(entry.get("file", "")).strip()
    if not file_ref:
        raise FixtureError(f"{label}: 'file' is required")
    return safe_resolve(
        config.root,
        base / file_ref,
        allow_symlinks=config.limits.allow_symlinks,
        max_path_length=config.limits.max_path_length,
        must_exist=True,
    )


def _entry_name(entry: Mapping[str, Any], target: Path) -> str:
    name = str(entry.get("name", "") or "").strip()
    return name or target.stem


def _check_expectation(entry: Mapping[str, Any], kind: FixtureKind, label: str) -> None:
    """Verify the manifest's ``expected`` value agrees with the section it sits in.

    A case filed under ``negative_cases`` but marked ``match`` is a contradiction,
    and silently trusting either side would make the suite assert the wrong thing.
    """
    expected = entry.get("expected")
    if expected is None:
        return
    text = str(expected).strip().lower()
    wanted = "match" if kind is FixtureKind.POSITIVE else "no_match"
    if text not in {"match", "no_match"}:
        raise FixtureError(f"{label}: 'expected' must be 'match' or 'no_match', got {expected!r}")
    if text != wanted:
        raise FixtureError(
            f"{label}: entry is listed as {kind.value} but declares expected={text!r}"
        )


def _describe(entry: Mapping[str, Any]) -> str:
    scenario = str(entry.get("scenario", "") or "").strip()
    rationale = str(entry.get("rationale", "") or "").strip()
    if scenario and rationale:
        return f"{scenario} {rationale}"
    return scenario or rationale


def load_case_manifest(
    manifest_path: Path,
    *,
    config: LabConfig,
) -> tuple[list[FixtureCase], list[tuple[str, str]]]:
    """Load one ``fixtures/rules/<catalog_id>/manifest.json``.

    Each listed file contributes its events as individual cases, so a file holding
    one event yields one case and the manifest's counts stay meaningful.
    """
    data, relative = _read_manifest(manifest_path, config=config)
    catalog_id = str(data.get("catalog_id", "") or "").strip()
    if not catalog_id:
        raise FixtureError(f"{relative}: 'catalog_id' is required")

    base = manifest_path.parent
    cases: list[FixtureCase] = []
    errors: list[tuple[str, str]] = []

    for section, kind in CASE_SECTIONS:
        entries = data.get(section) or []
        if not isinstance(entries, Sequence) or isinstance(entries, str):
            errors.append((relative, f"{relative}: '{section}' must be a list"))
            continue
        for index, entry in enumerate(entries):
            label = f"{relative}.{section}[{index}]"
            try:
                if not isinstance(entry, Mapping):
                    raise FixtureError(f"{label}: entry must be an object")
                _check_expectation(entry, kind, label)
                target = _resolve_entry_file(entry, base, label, config)
                events = load_jsonl_events(target, config=config)
                if not events:
                    raise FixtureError(f"{label}: fixture file holds no events")
                name = _entry_name(entry, target)
                source = relative_display(config.root, target)
                description = _describe(entry)
                for offset, event in enumerate(events):
                    suffix = f"{name}" if len(events) == 1 else f"{name}#{offset + 1}"
                    cases.append(
                        FixtureCase(
                            case_id=f"{catalog_id}::{kind.value}::{suffix}",
                            catalog_id=catalog_id,
                            kind=kind,
                            event=event,
                            description=description,
                            source_path=source,
                        )
                    )
            except (FixtureError, PathSafetyError) as exc:
                errors.append((label, str(exc)))

    return cases, errors


def load_sequence_manifest(
    manifest_path: Path,
    *,
    config: LabConfig,
) -> tuple[list[CorrelationSequence], list[tuple[str, str]]]:
    """Load one ``fixtures/correlation/<catalog_id>/manifest.json``.

    Each listed file is one ordered sequence. When the manifest states an
    ``event_count`` it is enforced, which catches a sequence that lost a line.
    """
    data, relative = _read_manifest(manifest_path, config=config)
    catalog_id = str(data.get("catalog_id", "") or "").strip()
    if not catalog_id:
        raise FixtureError(f"{relative}: 'catalog_id' is required")

    base = manifest_path.parent
    sequences: list[CorrelationSequence] = []
    errors: list[tuple[str, str]] = []

    for section, kind in SEQUENCE_SECTIONS:
        entries = data.get(section) or []
        if not isinstance(entries, Sequence) or isinstance(entries, str):
            errors.append((relative, f"{relative}: '{section}' must be a list"))
            continue
        for index, entry in enumerate(entries):
            label = f"{relative}.{section}[{index}]"
            try:
                if not isinstance(entry, Mapping):
                    raise FixtureError(f"{label}: entry must be an object")
                _check_expectation(entry, kind, label)
                target = _resolve_entry_file(entry, base, label, config)
                events = load_jsonl_events(
                    target,
                    config=config,
                    max_events=config.limits.max_correlation_sequence_events,
                )
                declared = entry.get("event_count")
                counted = isinstance(declared, int) and not isinstance(declared, bool)
                if counted and declared != len(events):
                    raise FixtureError(
                        f"{label}: manifest declares {declared} event(s) but the file "
                        f"holds {len(events)}"
                    )
                name = _entry_name(entry, target)
                sequences.append(
                    _build_sequence(
                        events,
                        catalog_id=catalog_id,
                        kind=kind,
                        sequence_id=f"{catalog_id}::{kind.value}::{name}",
                        source=relative_display(config.root, target),
                        description=_describe(entry),
                        limit=config.limits.max_correlation_sequence_events,
                    )
                )
            except (FixtureError, PathSafetyError) as exc:
                errors.append((label, str(exc)))

    return sequences, errors


def load_by_catalog_layout(fixtures_root: Path, *, config: LabConfig) -> FixtureSet:
    """Load the ``fixtures/rules`` and ``fixtures/correlation`` layout."""
    cases: list[FixtureCase] = []
    sequences: list[CorrelationSequence] = []
    errors: list[tuple[str, str]] = []

    for subdirectory, loader in (
        (RULES_SUBDIRECTORY, load_case_manifest),
        (CORRELATION_SUBDIRECTORY, load_sequence_manifest),
    ):
        parent = fixtures_root / subdirectory
        if not parent.is_dir():
            continue
        for directory in sorted(entry for entry in parent.iterdir() if entry.is_dir()):
            if directory.name in EXCLUDED_DIRECTORIES:
                continue
            manifest = directory / MANIFEST_NAME
            relative = relative_display(config.root, directory)
            if not manifest.is_file():
                errors.append(
                    (
                        relative,
                        f"{relative}: no {MANIFEST_NAME}; a fixture directory must declare "
                        "what each file is expected to prove",
                    )
                )
                continue
            try:
                loaded, problems = loader(manifest, config=config)
            except (FixtureError, PathSafetyError) as exc:
                errors.append((relative_display(config.root, manifest), str(exc)))
                continue
            errors.extend(problems)
            if subdirectory == RULES_SUBDIRECTORY:
                cases.extend(loaded)  # type: ignore[arg-type]
            else:
                sequences.extend(loaded)  # type: ignore[arg-type]

    return FixtureSet(
        cases=tuple(cases),
        sequences=tuple(sequences),
        errors=tuple(errors),
        banner=config.synthetic_banner,
        manifest_used=True,
    )


def load_from_manifest(
    manifest_path: Path,
    *,
    config: LabConfig,
) -> FixtureSet:
    """Load fixtures listed in ``manifest.json``.

    Raises:
        FixtureError: if the manifest itself is malformed. Individual fixture
            files that fail are collected into :attr:`FixtureSet.errors` so one
            bad file does not hide the rest of the suite.
    """
    relative = relative_display(config.root, manifest_path)
    try:
        text = safe_read_text(manifest_path, max_bytes=config.limits.max_file_bytes)
        data = json.loads(text)
    except PathSafetyError as exc:
        raise FixtureError(f"{relative}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FixtureError(f"{relative}: invalid JSON: {exc}") from exc

    if not isinstance(data, Mapping):
        raise FixtureError(f"{relative}: manifest root must be an object")

    banner = str(data.get("synthetic_banner", SYNTHETIC_DATA_BANNER))
    fixtures_root = manifest_path.parent
    cases: list[FixtureCase] = []
    sequences: list[CorrelationSequence] = []
    errors: list[tuple[str, str]] = []

    for index, entry in enumerate(data.get("entries", []) or []):
        label = f"{relative}.entries[{index}]"
        try:
            if not isinstance(entry, Mapping):
                raise FixtureError(f"{label}: entry must be an object")
            catalog_id = str(entry.get("catalog_id", "")).strip()
            if not catalog_id:
                raise FixtureError(f"{label}: 'catalog_id' is required")
            kind = _parse_kind(entry.get("kind"), label)
            file_ref = str(entry.get("file", "")).strip()
            if not file_ref:
                raise FixtureError(f"{label}: 'file' is required")
            target = safe_resolve(
                config.root,
                fixtures_root / file_ref,
                allow_symlinks=config.limits.allow_symlinks,
                max_path_length=config.limits.max_path_length,
                must_exist=True,
            )
            events = load_jsonl_events(target, config=config)
            cases.extend(
                _build_cases(
                    events,
                    catalog_id=catalog_id,
                    kind=kind,
                    source=relative_display(config.root, target),
                    description=str(entry.get("description", "")),
                )
            )
        except (FixtureError, PathSafetyError) as exc:
            errors.append((label, str(exc)))

    for index, entry in enumerate(data.get("sequences", []) or []):
        label = f"{relative}.sequences[{index}]"
        try:
            if not isinstance(entry, Mapping):
                raise FixtureError(f"{label}: entry must be an object")
            catalog_id = str(entry.get("catalog_id", "")).strip()
            if not catalog_id:
                raise FixtureError(f"{label}: 'catalog_id' is required")
            kind = _parse_kind(entry.get("kind"), label)
            file_ref = str(entry.get("file", "")).strip()
            if not file_ref:
                raise FixtureError(f"{label}: 'file' is required")
            target = safe_resolve(
                config.root,
                fixtures_root / file_ref,
                allow_symlinks=config.limits.allow_symlinks,
                max_path_length=config.limits.max_path_length,
                must_exist=True,
            )
            events = load_jsonl_events(
                target,
                config=config,
                max_events=config.limits.max_correlation_sequence_events,
            )
            sequence_id = str(entry.get("sequence_id", target.stem)).strip()
            sequences.append(
                _build_sequence(
                    events,
                    catalog_id=catalog_id,
                    kind=kind,
                    sequence_id=f"{catalog_id}::{kind.value}::{sequence_id}",
                    source=relative_display(config.root, target),
                    description=str(entry.get("description", "")),
                    limit=config.limits.max_correlation_sequence_events,
                )
            )
        except (FixtureError, PathSafetyError) as exc:
            errors.append((label, str(exc)))

    return FixtureSet(
        cases=tuple(cases),
        sequences=tuple(sequences),
        errors=tuple(errors),
        banner=banner,
        manifest_used=True,
    )


def load_by_convention(fixtures_root: Path, *, config: LabConfig) -> FixtureSet:
    """Discover fixtures from the directory layout, without a manifest."""
    cases: list[FixtureCase] = []
    sequences: list[CorrelationSequence] = []
    errors: list[tuple[str, str]] = []

    if not fixtures_root.is_dir():
        return FixtureSet(banner=config.synthetic_banner)

    for directory in sorted(entry for entry in fixtures_root.iterdir() if entry.is_dir()):
        if directory.name in EXCLUDED_DIRECTORIES:
            continue
        catalog_id = directory.name

        for filename, kind in (
            (POSITIVE_FILE, FixtureKind.POSITIVE),
            (NEGATIVE_FILE, FixtureKind.NEGATIVE),
        ):
            candidate = directory / filename
            if not candidate.is_file():
                continue
            label = relative_display(config.root, candidate)
            try:
                target = safe_resolve(
                    config.root,
                    candidate,
                    allow_symlinks=config.limits.allow_symlinks,
                    max_path_length=config.limits.max_path_length,
                )
                cases.extend(
                    _build_cases(
                        load_jsonl_events(target, config=config),
                        catalog_id=catalog_id,
                        kind=kind,
                        source=label,
                    )
                )
            except (FixtureError, PathSafetyError) as exc:
                errors.append((label, str(exc)))

        sequence_dir = directory / SEQUENCES_DIRECTORY
        if not sequence_dir.is_dir():
            continue
        for candidate in sorted(sequence_dir.glob("*.jsonl")):
            label = relative_display(config.root, candidate)
            sequence_kind = _sequence_kind_from_name(candidate.name)
            if sequence_kind is None:
                errors.append(
                    (
                        label,
                        "sequence filename must contain 'positive' or 'negative' so its "
                        "expected outcome is unambiguous",
                    )
                )
                continue
            try:
                target = safe_resolve(
                    config.root,
                    candidate,
                    allow_symlinks=config.limits.allow_symlinks,
                    max_path_length=config.limits.max_path_length,
                )
                events = load_jsonl_events(
                    target,
                    config=config,
                    max_events=config.limits.max_correlation_sequence_events,
                )
                sequences.append(
                    _build_sequence(
                        events,
                        catalog_id=catalog_id,
                        kind=sequence_kind,
                        sequence_id=f"{catalog_id}::{sequence_kind.value}::{target.stem}",
                        source=label,
                        limit=config.limits.max_correlation_sequence_events,
                    )
                )
            except (FixtureError, PathSafetyError) as exc:
                errors.append((label, str(exc)))

    return FixtureSet(
        cases=tuple(cases),
        sequences=tuple(sequences),
        errors=tuple(errors),
        banner=config.synthetic_banner,
        manifest_used=False,
    )


def load_fixtures(config: LabConfig, *, fixtures_root: Path | None = None) -> FixtureSet:
    """Load every fixture, preferring the per-rule catalog layout."""
    root = fixtures_root if fixtures_root is not None else config.fixtures_dir
    if not root.is_dir():
        return FixtureSet(banner=config.synthetic_banner)

    if (root / RULES_SUBDIRECTORY).is_dir() or (root / CORRELATION_SUBDIRECTORY).is_dir():
        return load_by_catalog_layout(root, config=config)

    manifest = root / MANIFEST_NAME
    if manifest.is_file():
        return load_from_manifest(manifest, config=config)
    return load_by_convention(root, config=config)


def write_jsonl(path: Path, events: Sequence[SyntheticEvent]) -> None:
    """Write events as JSONL with stable key order and LF endings."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(json.dumps(event.to_mapping(), sort_keys=True, ensure_ascii=False))
            handle.write("\n")


__all__ = [
    "CORRELATION_SUBDIRECTORY",
    "EXCLUDED_DIRECTORIES",
    "MANIFEST_NAME",
    "NEGATIVE_FILE",
    "POSITIVE_FILE",
    "RULES_SUBDIRECTORY",
    "SEQUENCES_DIRECTORY",
    "FixtureSet",
    "load_by_catalog_layout",
    "load_by_convention",
    "load_case_manifest",
    "load_fixtures",
    "load_from_manifest",
    "load_jsonl_events",
    "load_sequence_manifest",
    "write_jsonl",
]
