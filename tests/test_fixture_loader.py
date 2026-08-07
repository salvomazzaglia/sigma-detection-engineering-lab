"""Fixture loading: JSONL records, manifests, layouts, and error collection."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from tests.conftest import (
    event_record,
    make_case,
    make_event,
    make_sequence,
    write_json,
    write_jsonl_records,
)

from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.errors import FixtureError
from sigma_detection_engineering_lab.fixture_loader import (
    CORRELATION_SUBDIRECTORY,
    EXCLUDED_DIRECTORIES,
    MANIFEST_NAME,
    RULES_SUBDIRECTORY,
    FixtureSet,
    load_by_catalog_layout,
    load_by_convention,
    load_case_manifest,
    load_fixtures,
    load_from_manifest,
    load_jsonl_events,
    load_sequence_manifest,
    write_jsonl,
)
from sigma_detection_engineering_lab.models import FixtureKind


def case_dir(project: Path, catalog_id: str = "SDEL-TST-001") -> Path:
    target = project / "fixtures" / RULES_SUBDIRECTORY / catalog_id
    target.mkdir(parents=True, exist_ok=True)
    return target


def sequence_dir(project: Path, catalog_id: str = "SDEL-COR-001") -> Path:
    target = project / "fixtures" / CORRELATION_SUBDIRECTORY / catalog_id
    target.mkdir(parents=True, exist_ok=True)
    return target


def case_manifest(catalog_id: str = "SDEL-TST-001", **overrides: Any) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "catalog_id": catalog_id,
        "positive_cases": [{"file": "positive/case_01.jsonl", "expected": "match"}],
        "negative_cases": [{"file": "negative/case_01.jsonl", "expected": "no_match"}],
    }
    manifest.update(overrides)
    return manifest


@pytest.fixture
def fixture_project(tiny_project: Path) -> Path:
    """A project with one positive and one negative case fixture."""
    directory = case_dir(tiny_project)
    write_jsonl_records(directory / "positive" / "case_01.jsonl", [event_record("EVT-P1")])
    write_jsonl_records(
        directory / "negative" / "case_01.jsonl",
        [event_record("EVT-N1", fields={"Image": "C:\\Windows\\explorer.exe"})],
    )
    write_json(directory / MANIFEST_NAME, case_manifest())
    return tiny_project


class TestJsonlEvents:
    def test_a_single_record_loads(self, tiny_config: LabConfig, tmp_path: Path) -> None:
        path = write_jsonl_records(tiny_config.root / "fixtures" / "a.jsonl", [event_record()])
        assert len(load_jsonl_events(path, config=tiny_config)) == 1

    def test_multiple_records_load_in_order(self, tiny_config: LabConfig) -> None:
        path = write_jsonl_records(
            tiny_config.root / "fixtures" / "a.jsonl",
            [event_record("EVT-1"), event_record("EVT-2")],
        )
        events = load_jsonl_events(path, config=tiny_config)
        assert [event.event_id for event in events] == ["EVT-1", "EVT-2"]

    def test_blank_lines_are_ignored(self, tiny_config: LabConfig) -> None:
        path = tiny_config.root / "fixtures" / "a.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        write_jsonl_records(path, [event_record()])
        path.write_text(path.read_text(encoding="utf-8") + "\n\n   \n", encoding="utf-8")
        assert len(load_jsonl_events(path, config=tiny_config)) == 1

    def test_an_empty_file_yields_no_events(self, tiny_config: LabConfig) -> None:
        path = tiny_config.root / "fixtures" / "empty.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
        assert load_jsonl_events(path, config=tiny_config) == []

    def test_invalid_json_reports_the_line_number(self, tiny_config: LabConfig) -> None:
        path = tiny_config.root / "fixtures" / "a.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        write_jsonl_records(path, [event_record()])
        path.write_text(path.read_text(encoding="utf-8") + "not json\n", encoding="utf-8")
        with pytest.raises(FixtureError, match=":2: invalid JSON"):
            load_jsonl_events(path, config=tiny_config)

    def test_a_non_object_line_is_refused(self, tiny_config: LabConfig) -> None:
        path = tiny_config.root / "fixtures" / "a.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("[1, 2]\n", encoding="utf-8")
        with pytest.raises(FixtureError, match="must be a JSON object"):
            load_jsonl_events(path, config=tiny_config)

    def test_a_nul_byte_is_refused(self, tiny_config: LabConfig) -> None:
        path = tiny_config.root / "fixtures" / "a.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'{"a": 1}\x00\n')
        with pytest.raises(FixtureError, match="NUL byte"):
            load_jsonl_events(path, config=tiny_config)

    def test_a_missing_file_is_refused(self, tiny_config: LabConfig) -> None:
        with pytest.raises(FixtureError):
            load_jsonl_events(tiny_config.root / "absent.jsonl", config=tiny_config)

    def test_the_event_count_limit_is_enforced(self, tiny_config: LabConfig) -> None:
        path = write_jsonl_records(
            tiny_config.root / "fixtures" / "a.jsonl",
            [event_record(f"EVT-{index}") for index in range(4)],
        )
        with pytest.raises(FixtureError, match="more than 2 events"):
            load_jsonl_events(path, config=tiny_config, max_events=2)

    def test_a_file_at_the_limit_is_accepted(self, tiny_config: LabConfig) -> None:
        path = write_jsonl_records(
            tiny_config.root / "fixtures" / "a.jsonl",
            [event_record(f"EVT-{index}") for index in range(2)],
        )
        assert len(load_jsonl_events(path, config=tiny_config, max_events=2)) == 2

    def test_a_record_marked_non_synthetic_is_refused(self, tiny_config: LabConfig) -> None:
        record = event_record()
        record["synthetic"] = False
        path = write_jsonl_records(tiny_config.root / "fixtures" / "a.jsonl", [record])
        with pytest.raises(FixtureError, match="'synthetic' must be true"):
            load_jsonl_events(path, config=tiny_config)

    def test_an_absent_synthetic_marker_defaults_to_true(self, tiny_config: LabConfig) -> None:
        record = event_record()
        del record["synthetic"]
        path = write_jsonl_records(tiny_config.root / "fixtures" / "a.jsonl", [record])
        assert load_jsonl_events(path, config=tiny_config)[0].synthetic is True

    def test_an_oversized_file_is_refused(self, tiny_config: LabConfig) -> None:
        path = tiny_config.root / "fixtures" / "a.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x" * (tiny_config.limits.max_file_bytes + 1), encoding="utf-8")
        with pytest.raises(FixtureError):
            load_jsonl_events(path, config=tiny_config)

    def test_fields_survive_the_round_trip(self, tiny_config: LabConfig) -> None:
        path = write_jsonl_records(
            tiny_config.root / "fixtures" / "a.jsonl",
            [event_record(fields={"Image": "C:\\a.exe", "CommandLine": "a.exe -x"})],
        )
        event = load_jsonl_events(path, config=tiny_config)[0]
        assert event.fields["CommandLine"] == "a.exe -x"

    def test_the_logsource_survives_the_round_trip(self, tiny_config: LabConfig) -> None:
        path = write_jsonl_records(tiny_config.root / "fixtures" / "a.jsonl", [event_record()])
        event = load_jsonl_events(path, config=tiny_config)[0]
        assert event.category == "process_creation"
        assert event.product == "windows"


class TestWriteJsonl:
    def test_events_round_trip_through_disk(self, tiny_config: LabConfig) -> None:
        path = tiny_config.root / "fixtures" / "out.jsonl"
        write_jsonl(path, [make_event("EVT-1"), make_event("EVT-2")])
        assert [e.event_id for e in load_jsonl_events(path, config=tiny_config)] == [
            "EVT-1",
            "EVT-2",
        ]

    def test_parent_directories_are_created(self, tmp_path: Path) -> None:
        target = tmp_path / "a" / "b" / "out.jsonl"
        write_jsonl(target, [make_event()])
        assert target.is_file()

    def test_line_endings_are_lf(self, tmp_path: Path) -> None:
        target = tmp_path / "out.jsonl"
        write_jsonl(target, [make_event()])
        assert b"\r\n" not in target.read_bytes()

    def test_an_empty_sequence_writes_an_empty_file(self, tmp_path: Path) -> None:
        target = tmp_path / "out.jsonl"
        write_jsonl(target, [])
        assert target.read_text(encoding="utf-8") == ""


class TestFixtureSetQueries:
    def test_cases_are_filtered_by_catalog_id(self) -> None:
        fixtures = FixtureSet(cases=(make_case("A"), make_case("B")))
        assert len(fixtures.cases_for("A")) == 1

    def test_cases_are_filtered_by_kind(self) -> None:
        fixtures = FixtureSet(cases=(make_case("A"), make_case("A", kind=FixtureKind.NEGATIVE)))
        assert len(fixtures.cases_for("A", FixtureKind.POSITIVE)) == 1

    def test_an_unknown_catalog_id_yields_nothing(self) -> None:
        assert FixtureSet(cases=(make_case("A"),)).cases_for("Z") == ()

    def test_sequences_are_filtered_by_catalog_id(self) -> None:
        fixtures = FixtureSet(sequences=(make_sequence("A", events=(make_event(),)),))
        assert len(fixtures.sequences_for("A")) == 1

    def test_sequences_are_filtered_by_kind(self) -> None:
        fixtures = FixtureSet(
            sequences=(
                make_sequence("A", events=(make_event(),)),
                make_sequence("A", kind=FixtureKind.NEGATIVE, events=(make_event(),)),
            )
        )
        assert len(fixtures.sequences_for("A", FixtureKind.NEGATIVE)) == 1

    def test_covered_ids_include_cases_and_sequences(self) -> None:
        fixtures = FixtureSet(
            cases=(make_case("A"),), sequences=(make_sequence("B", events=(make_event(),)),)
        )
        assert fixtures.covered_catalog_ids() == frozenset({"A", "B"})

    def test_an_empty_set_covers_nothing(self, empty_fixture_set: FixtureSet) -> None:
        assert empty_fixture_set.covered_catalog_ids() == frozenset()

    def test_counts_report_all_four_buckets(self) -> None:
        counts = FixtureSet().counts_for("A")
        assert set(counts) == {
            "positive_events",
            "negative_events",
            "positive_sequences",
            "negative_sequences",
        }

    def test_counts_are_accurate(self) -> None:
        fixtures = FixtureSet(
            cases=(make_case("A"), make_case("A"), make_case("A", kind=FixtureKind.NEGATIVE))
        )
        counts = fixtures.counts_for("A")
        assert counts["positive_events"] == 2
        assert counts["negative_events"] == 1

    def test_the_summary_reports_counts(self) -> None:
        payload = FixtureSet(cases=(make_case(),), errors=(("a", "b"),)).to_dict()
        assert payload["case_count"] == 1
        assert payload["error_count"] == 1

    def test_the_summary_carries_the_banner(self, empty_fixture_set: FixtureSet) -> None:
        assert "synthetic" in empty_fixture_set.to_dict()["banner"].lower()


class TestCaseManifest:
    def test_a_valid_manifest_loads_both_kinds(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        cases, errors = load_case_manifest(manifest, config=tiny_config)
        assert errors == []
        assert len(cases) == 2

    def test_case_ids_encode_the_kind(self, tiny_config: LabConfig, fixture_project: Path) -> None:
        cases, _ = load_case_manifest(case_dir(fixture_project) / MANIFEST_NAME, config=tiny_config)
        assert any("::positive::" in case.case_id for case in cases)
        assert any("::negative::" in case.case_id for case in cases)

    def test_a_manifest_without_a_catalog_id_is_refused(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        write_json(manifest, {"positive_cases": []})
        with pytest.raises(FixtureError, match="'catalog_id' is required"):
            load_case_manifest(manifest, config=tiny_config)

    def test_a_non_object_root_is_refused(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        manifest.write_text("[]", encoding="utf-8")
        with pytest.raises(FixtureError, match="must be an object"):
            load_case_manifest(manifest, config=tiny_config)

    def test_invalid_manifest_json_is_refused(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        manifest.write_text("{", encoding="utf-8")
        with pytest.raises(FixtureError, match="invalid JSON"):
            load_case_manifest(manifest, config=tiny_config)

    def test_a_section_that_is_not_a_list_is_an_error(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        write_json(manifest, case_manifest(positive_cases="one"))
        _, errors = load_case_manifest(manifest, config=tiny_config)
        assert any("must be a list" in message for _, message in errors)

    def test_a_non_object_entry_is_an_error(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        write_json(manifest, case_manifest(positive_cases=["file.jsonl"]))
        _, errors = load_case_manifest(manifest, config=tiny_config)
        assert any("must be an object" in message for _, message in errors)

    def test_an_entry_without_a_file_is_an_error(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        write_json(manifest, case_manifest(positive_cases=[{"name": "x"}]))
        _, errors = load_case_manifest(manifest, config=tiny_config)
        assert any("'file' is required" in message for _, message in errors)

    def test_a_missing_target_file_is_an_error(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        write_json(manifest, case_manifest(positive_cases=[{"file": "positive/absent.jsonl"}]))
        _, errors = load_case_manifest(manifest, config=tiny_config)
        assert len(errors) == 1

    def test_an_empty_fixture_file_is_an_error(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        (case_dir(fixture_project) / "positive" / "case_01.jsonl").write_text("", encoding="utf-8")
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        _, errors = load_case_manifest(manifest, config=tiny_config)
        assert any("holds no events" in message for _, message in errors)

    def test_a_contradictory_expectation_is_an_error(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        write_json(
            manifest,
            case_manifest(
                positive_cases=[{"file": "positive/case_01.jsonl", "expected": "no_match"}]
            ),
        )
        _, errors = load_case_manifest(manifest, config=tiny_config)
        assert any("declares expected" in message for _, message in errors)

    def test_an_unknown_expectation_word_is_an_error(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        write_json(
            manifest,
            case_manifest(positive_cases=[{"file": "positive/case_01.jsonl", "expected": "maybe"}]),
        )
        _, errors = load_case_manifest(manifest, config=tiny_config)
        assert any("'expected' must be" in message for _, message in errors)

    def test_an_absent_expectation_is_allowed(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        write_json(
            manifest,
            case_manifest(positive_cases=[{"file": "positive/case_01.jsonl"}], negative_cases=[]),
        )
        cases, errors = load_case_manifest(manifest, config=tiny_config)
        assert errors == []
        assert len(cases) == 1

    def test_a_multi_event_file_yields_numbered_cases(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        write_jsonl_records(
            case_dir(fixture_project) / "positive" / "case_01.jsonl",
            [event_record("EVT-1"), event_record("EVT-2")],
        )
        cases, _ = load_case_manifest(case_dir(fixture_project) / MANIFEST_NAME, config=tiny_config)
        assert any(case.case_id.endswith("#2") for case in cases)

    def test_the_scenario_and_rationale_form_the_description(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        write_json(
            manifest,
            case_manifest(
                positive_cases=[
                    {
                        "file": "positive/case_01.jsonl",
                        "scenario": "Staged binary.",
                        "rationale": "Path is unmanaged.",
                    }
                ],
                negative_cases=[],
            ),
        )
        cases, _ = load_case_manifest(manifest, config=tiny_config)
        assert cases[0].description == "Staged binary. Path is unmanaged."

    def test_an_explicit_name_is_used_in_the_case_id(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        write_json(
            manifest,
            case_manifest(
                positive_cases=[{"file": "positive/case_01.jsonl", "name": "staged_binary"}],
                negative_cases=[],
            ),
        )
        cases, _ = load_case_manifest(manifest, config=tiny_config)
        assert cases[0].case_id.endswith("staged_binary")

    def test_a_file_reference_escaping_the_root_is_an_error(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        write_json(manifest, case_manifest(positive_cases=[{"file": "../../../../etc/passwd"}]))
        _, errors = load_case_manifest(manifest, config=tiny_config)
        assert len(errors) >= 1

    def test_one_bad_entry_does_not_hide_the_good_ones(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        manifest = case_dir(fixture_project) / MANIFEST_NAME
        write_json(
            manifest,
            case_manifest(
                positive_cases=[
                    {"file": "positive/case_01.jsonl"},
                    {"file": "positive/absent.jsonl"},
                ],
                negative_cases=[],
            ),
        )
        cases, errors = load_case_manifest(manifest, config=tiny_config)
        assert len(cases) == 1
        assert len(errors) == 1


class TestSequenceManifest:
    @pytest.fixture
    def correlation_project(self, tiny_project: Path) -> Path:
        directory = sequence_dir(tiny_project)
        write_jsonl_records(
            directory / "positive" / "sequence_01.jsonl",
            [event_record("EVT-1", offset_seconds=0), event_record("EVT-2", offset_seconds=30)],
        )
        write_json(
            directory / MANIFEST_NAME,
            {
                "catalog_id": "SDEL-COR-001",
                "positive_sequences": [{"file": "positive/sequence_01.jsonl", "event_count": 2}],
            },
        )
        return tiny_project

    def test_a_valid_sequence_manifest_loads(
        self, tiny_config: LabConfig, correlation_project: Path
    ) -> None:
        manifest = sequence_dir(correlation_project) / MANIFEST_NAME
        sequences, errors = load_sequence_manifest(manifest, config=tiny_config)
        assert errors == []
        assert len(sequences) == 1

    def test_events_are_sorted_by_timestamp(
        self, tiny_config: LabConfig, correlation_project: Path
    ) -> None:
        write_jsonl_records(
            sequence_dir(correlation_project) / "positive" / "sequence_01.jsonl",
            [event_record("EVT-late", offset_seconds=60), event_record("EVT-early")],
        )
        manifest = sequence_dir(correlation_project) / MANIFEST_NAME
        sequences, _ = load_sequence_manifest(manifest, config=tiny_config)
        assert [event.event_id for event in sequences[0].events] == ["EVT-early", "EVT-late"]

    def test_a_wrong_declared_count_is_an_error(
        self, tiny_config: LabConfig, correlation_project: Path
    ) -> None:
        manifest = sequence_dir(correlation_project) / MANIFEST_NAME
        write_json(
            manifest,
            {
                "catalog_id": "SDEL-COR-001",
                "positive_sequences": [{"file": "positive/sequence_01.jsonl", "event_count": 5}],
            },
        )
        _, errors = load_sequence_manifest(manifest, config=tiny_config)
        assert any("declares 5 event" in message for _, message in errors)

    def test_an_absent_declared_count_is_allowed(
        self, tiny_config: LabConfig, correlation_project: Path
    ) -> None:
        manifest = sequence_dir(correlation_project) / MANIFEST_NAME
        write_json(
            manifest,
            {
                "catalog_id": "SDEL-COR-001",
                "positive_sequences": [{"file": "positive/sequence_01.jsonl"}],
            },
        )
        _, errors = load_sequence_manifest(manifest, config=tiny_config)
        assert errors == []

    def test_an_empty_sequence_file_is_an_error(
        self, tiny_config: LabConfig, correlation_project: Path
    ) -> None:
        (sequence_dir(correlation_project) / "positive" / "sequence_01.jsonl").write_text(
            "", encoding="utf-8"
        )
        manifest = sequence_dir(correlation_project) / MANIFEST_NAME
        _, errors = load_sequence_manifest(manifest, config=tiny_config)
        assert len(errors) == 1

    def test_a_manifest_without_a_catalog_id_is_refused(
        self, tiny_config: LabConfig, correlation_project: Path
    ) -> None:
        manifest = sequence_dir(correlation_project) / MANIFEST_NAME
        write_json(manifest, {"positive_sequences": []})
        with pytest.raises(FixtureError, match="'catalog_id' is required"):
            load_sequence_manifest(manifest, config=tiny_config)

    def test_a_contradictory_expectation_is_an_error(
        self, tiny_config: LabConfig, correlation_project: Path
    ) -> None:
        manifest = sequence_dir(correlation_project) / MANIFEST_NAME
        write_json(
            manifest,
            {
                "catalog_id": "SDEL-COR-001",
                "positive_sequences": [
                    {"file": "positive/sequence_01.jsonl", "expected": "no_match"}
                ],
            },
        )
        _, errors = load_sequence_manifest(manifest, config=tiny_config)
        assert len(errors) == 1

    def test_a_sequence_over_the_limit_is_an_error(
        self, tiny_config: LabConfig, correlation_project: Path
    ) -> None:
        write_jsonl_records(
            sequence_dir(correlation_project) / "positive" / "sequence_01.jsonl",
            [event_record(f"EVT-{index}", offset_seconds=index) for index in range(4)],
        )
        manifest = sequence_dir(correlation_project) / MANIFEST_NAME
        write_json(
            manifest,
            {
                "catalog_id": "SDEL-COR-001",
                "positive_sequences": [{"file": "positive/sequence_01.jsonl"}],
            },
        )
        narrow = replace(
            tiny_config,
            limits=replace(tiny_config.limits, max_correlation_sequence_events=2),
        )
        _, errors = load_sequence_manifest(manifest, config=narrow)
        assert len(errors) == 1


class TestCatalogLayout:
    def test_the_layout_loads_cases(self, tiny_config: LabConfig, fixture_project: Path) -> None:
        fixtures = load_by_catalog_layout(fixture_project / "fixtures", config=tiny_config)
        assert len(fixtures.cases) == 2

    def test_the_layout_marks_the_manifest_as_used(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        assert (
            load_by_catalog_layout(fixture_project / "fixtures", config=tiny_config).manifest_used
            is True
        )

    def test_a_directory_without_a_manifest_is_an_error(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        (fixture_project / "fixtures" / RULES_SUBDIRECTORY / "SDEL-TST-002").mkdir()
        fixtures = load_by_catalog_layout(fixture_project / "fixtures", config=tiny_config)
        assert any(f"no {MANIFEST_NAME}" in message for _, message in fixtures.errors)

    @pytest.mark.parametrize("name", sorted(EXCLUDED_DIRECTORIES))
    def test_excluded_directories_are_skipped(
        self, tiny_config: LabConfig, fixture_project: Path, name: str
    ) -> None:
        (fixture_project / "fixtures" / RULES_SUBDIRECTORY / name).mkdir()
        fixtures = load_by_catalog_layout(fixture_project / "fixtures", config=tiny_config)
        assert all(name not in path for path, _ in fixtures.errors)

    def test_a_broken_manifest_becomes_an_error_not_an_exception(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        (case_dir(fixture_project) / MANIFEST_NAME).write_text("{", encoding="utf-8")
        fixtures = load_by_catalog_layout(fixture_project / "fixtures", config=tiny_config)
        assert len(fixtures.errors) == 1

    def test_an_absent_layout_yields_nothing(self, tiny_config: LabConfig, tmp_path: Path) -> None:
        fixtures = load_by_catalog_layout(tmp_path / "nowhere", config=tiny_config)
        assert fixtures.cases == ()
        assert fixtures.sequences == ()


class TestFlatManifestLayout:
    @pytest.fixture
    def flat_project(self, tiny_project: Path) -> Path:
        root = tiny_project / "fixtures"
        write_jsonl_records(root / "a.jsonl", [event_record()])
        write_json(
            root / MANIFEST_NAME,
            {"entries": [{"catalog_id": "SDEL-TST-001", "kind": "positive", "file": "a.jsonl"}]},
        )
        return tiny_project

    def test_entries_are_loaded(self, tiny_config: LabConfig, flat_project: Path) -> None:
        fixtures = load_from_manifest(flat_project / "fixtures" / MANIFEST_NAME, config=tiny_config)
        assert len(fixtures.cases) == 1

    def test_an_unknown_kind_is_an_error(self, tiny_config: LabConfig, flat_project: Path) -> None:
        manifest = flat_project / "fixtures" / MANIFEST_NAME
        write_json(
            manifest,
            {"entries": [{"catalog_id": "A", "kind": "sideways", "file": "a.jsonl"}]},
        )
        fixtures = load_from_manifest(manifest, config=tiny_config)
        assert any("positive" in message for _, message in fixtures.errors)

    def test_a_missing_catalog_id_is_an_error(
        self, tiny_config: LabConfig, flat_project: Path
    ) -> None:
        manifest = flat_project / "fixtures" / MANIFEST_NAME
        write_json(manifest, {"entries": [{"kind": "positive", "file": "a.jsonl"}]})
        fixtures = load_from_manifest(manifest, config=tiny_config)
        assert len(fixtures.errors) == 1

    def test_a_custom_banner_is_honoured(self, tiny_config: LabConfig, flat_project: Path) -> None:
        manifest = flat_project / "fixtures" / MANIFEST_NAME
        write_json(manifest, {"synthetic_banner": "CUSTOM", "entries": []})
        assert load_from_manifest(manifest, config=tiny_config).banner == "CUSTOM"

    def test_sequences_are_loaded(self, tiny_config: LabConfig, flat_project: Path) -> None:
        root = flat_project / "fixtures"
        write_jsonl_records(root / "seq.jsonl", [event_record("EVT-1"), event_record("EVT-2")])
        manifest = root / MANIFEST_NAME
        write_json(
            manifest,
            {
                "sequences": [
                    {"catalog_id": "SDEL-COR-001", "kind": "positive", "file": "seq.jsonl"}
                ]
            },
        )
        assert len(load_from_manifest(manifest, config=tiny_config).sequences) == 1

    def test_an_invalid_manifest_raises(self, tiny_config: LabConfig, flat_project: Path) -> None:
        manifest = flat_project / "fixtures" / MANIFEST_NAME
        manifest.write_text("{", encoding="utf-8")
        with pytest.raises(FixtureError, match="invalid JSON"):
            load_from_manifest(manifest, config=tiny_config)


class TestConventionLayout:
    @pytest.fixture
    def convention_project(self, tiny_project: Path) -> Path:
        directory = tiny_project / "fixtures" / "SDEL-TST-001"
        write_jsonl_records(directory / "positive.jsonl", [event_record("EVT-P")])
        write_jsonl_records(directory / "negative.jsonl", [event_record("EVT-N")])
        return tiny_project

    def test_positive_and_negative_files_are_found(
        self, tiny_config: LabConfig, convention_project: Path
    ) -> None:
        fixtures = load_by_convention(convention_project / "fixtures", config=tiny_config)
        assert len(fixtures.cases) == 2

    def test_the_manifest_flag_is_false(
        self, tiny_config: LabConfig, convention_project: Path
    ) -> None:
        fixtures = load_by_convention(convention_project / "fixtures", config=tiny_config)
        assert fixtures.manifest_used is False

    def test_the_directory_name_becomes_the_catalog_id(
        self, tiny_config: LabConfig, convention_project: Path
    ) -> None:
        fixtures = load_by_convention(convention_project / "fixtures", config=tiny_config)
        assert fixtures.covered_catalog_ids() == frozenset({"SDEL-TST-001"})

    def test_sequences_need_a_kind_in_the_filename(
        self, tiny_config: LabConfig, convention_project: Path
    ) -> None:
        sequences = convention_project / "fixtures" / "SDEL-TST-001" / "sequences"
        write_jsonl_records(sequences / "ambiguous.jsonl", [event_record()])
        fixtures = load_by_convention(convention_project / "fixtures", config=tiny_config)
        assert any("positive" in message for _, message in fixtures.errors)

    def test_a_named_sequence_is_loaded(
        self, tiny_config: LabConfig, convention_project: Path
    ) -> None:
        sequences = convention_project / "fixtures" / "SDEL-TST-001" / "sequences"
        write_jsonl_records(sequences / "positive_01.jsonl", [event_record()])
        fixtures = load_by_convention(convention_project / "fixtures", config=tiny_config)
        assert len(fixtures.sequences) == 1

    def test_a_missing_root_yields_an_empty_set(
        self, tiny_config: LabConfig, tmp_path: Path
    ) -> None:
        assert load_by_convention(tmp_path / "nope", config=tiny_config).cases == ()


class TestLoadFixturesDispatch:
    def test_a_missing_fixtures_directory_is_empty(self, tiny_config: LabConfig) -> None:
        assert load_fixtures(tiny_config).cases == ()

    def test_the_catalog_layout_takes_priority(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        assert load_fixtures(tiny_config).manifest_used is True

    def test_an_explicit_root_is_honoured(
        self, tiny_config: LabConfig, fixture_project: Path
    ) -> None:
        fixtures = load_fixtures(tiny_config, fixtures_root=fixture_project / "fixtures")
        assert len(fixtures.cases) == 2

    def test_a_flat_manifest_is_used_when_no_catalog_layout_exists(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        root = tiny_project / "fixtures"
        write_jsonl_records(root / "a.jsonl", [event_record()])
        write_json(
            root / MANIFEST_NAME,
            {"entries": [{"catalog_id": "A", "kind": "positive", "file": "a.jsonl"}]},
        )
        assert len(load_fixtures(tiny_config).cases) == 1

    def test_convention_discovery_is_the_last_resort(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        write_jsonl_records(
            tiny_project / "fixtures" / "SDEL-TST-001" / "positive.jsonl", [event_record()]
        )
        fixtures = load_fixtures(tiny_config)
        assert fixtures.manifest_used is False
        assert len(fixtures.cases) == 1


class TestRealFixtures:
    def test_the_real_project_has_fixtures(self, real_fixtures: FixtureSet) -> None:
        assert len(real_fixtures.cases) > 0

    def test_no_real_fixture_failed_to_load(self, real_fixtures: FixtureSet) -> None:
        assert real_fixtures.errors == ()

    def test_the_real_project_uses_manifests(self, real_fixtures: FixtureSet) -> None:
        assert real_fixtures.manifest_used is True

    def test_every_real_case_belongs_to_a_rule(
        self, real_fixtures: FixtureSet, real_catalog: Any
    ) -> None:
        unknown = real_fixtures.covered_catalog_ids() - set(real_catalog.catalog_ids)
        assert unknown == frozenset()

    def test_every_real_event_is_marked_synthetic(self, real_fixtures: FixtureSet) -> None:
        assert all(case.event.synthetic for case in real_fixtures.cases)

    def test_case_identifiers_are_unique(self, real_fixtures: FixtureSet) -> None:
        ids = [case.case_id for case in real_fixtures.cases]
        assert len(set(ids)) == len(ids)
