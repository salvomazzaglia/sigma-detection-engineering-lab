"""The telemetry catalog: what a rule needs before it can work anywhere."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from conftest import make_rule, make_sidecar, write_json
from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.errors import TelemetryError
from sigma_detection_engineering_lab.metadata_loader import MetadataSet
from sigma_detection_engineering_lab.models import LogSource, TelemetryRequirement
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.severities import Severity
from sigma_detection_engineering_lab.telemetry import (
    CATALOG_FILENAME,
    TELEMETRY_ID_PATTERN,
    TelemetryCatalog,
    TelemetrySource,
    build_catalog,
    detection_field_names,
    load_telemetry_catalog,
    telemetry_usage,
    validate_catalog,
    validate_requirements,
)

SYSMON_PROFILE: dict[str, Any] = {
    "name": "Sysmon process creation",
    "logsource": {"product": "windows", "category": "process_creation"},
    "platform": "windows",
    "fields": ["Image", "CommandLine", "ParentImage", "User"],
    "channels": ["Microsoft-Windows-Sysmon/Operational"],
    "providers": ["Microsoft-Windows-Sysmon"],
    "required_logs": ["Sysmon Operational log"],
    "description": "Process creation events emitted by Sysmon event ID 1.",
}


def catalog_document(**profiles: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "profiles": profiles or {"sysmon_process_creation": dict(SYSMON_PROFILE)},
    }


def loaded(**profiles: Any) -> TelemetryCatalog:
    return build_catalog(catalog_document(**profiles))


class TestTelemetrySource:
    def test_a_source_keeps_its_identifier(self) -> None:
        assert TelemetrySource(telemetry_id="a").telemetry_id == "a"

    def test_has_field_is_true_for_a_documented_field(self) -> None:
        source = TelemetrySource(telemetry_id="a", fields=("Image",))
        assert source.has_field("Image") is True

    def test_has_field_ignores_case(self) -> None:
        source = TelemetrySource(telemetry_id="a", fields=("Image",))
        assert source.has_field("image") is True

    def test_has_field_ignores_surrounding_space(self) -> None:
        source = TelemetrySource(telemetry_id="a", fields=("Image",))
        assert source.has_field("  Image  ") is True

    def test_has_field_is_false_for_an_unknown_field(self) -> None:
        assert TelemetrySource(telemetry_id="a").has_field("Image") is False

    def test_has_channel_is_true_for_a_documented_channel(self) -> None:
        source = TelemetrySource(telemetry_id="a", channels=("Security",))
        assert source.has_channel("security") is True

    def test_has_channel_is_false_otherwise(self) -> None:
        assert TelemetrySource(telemetry_id="a").has_channel("Security") is False

    def test_to_dict_round_trips_the_identifier(self) -> None:
        assert TelemetrySource(telemetry_id="a").to_dict()["telemetry_id"] == "a"

    def test_to_dict_uses_lists_for_sequences(self) -> None:
        payload = TelemetrySource(telemetry_id="a", fields=("Image",)).to_dict()
        assert payload["fields"] == ["Image"]

    def test_a_source_is_frozen(self) -> None:
        with pytest.raises(FrozenInstanceError):
            TelemetrySource(telemetry_id="a").telemetry_id = "b"  # type: ignore[misc]


class TestBuildCatalog:
    def test_a_profile_becomes_a_source(self) -> None:
        assert loaded().get("sysmon_process_creation") is not None

    def test_the_schema_version_is_kept(self) -> None:
        assert loaded().schema_version == "1.0"

    def test_a_built_catalog_is_available(self) -> None:
        assert loaded().available is True

    def test_a_built_catalog_has_no_load_error(self) -> None:
        assert loaded().load_error is None

    def test_the_logsource_is_flattened(self) -> None:
        source = loaded().get("sysmon_process_creation")
        assert (source.product, source.category) == ("windows", "process_creation")

    def test_inline_logsource_parts_are_accepted(self) -> None:
        catalog = build_catalog({"profiles": {"a": {"product": "linux", "category": "auth"}}})
        assert catalog.get("a").product == "linux"

    def test_the_name_defaults_to_the_identifier(self) -> None:
        catalog = build_catalog({"profiles": {"a": {}}})
        assert catalog.get("a").name == "a"

    def test_a_single_string_field_is_wrapped(self) -> None:
        catalog = build_catalog({"profiles": {"a": {"fields": "Image"}}})
        assert catalog.get("a").fields == ("Image",)

    def test_optional_fields_are_read_as_fields(self) -> None:
        catalog = build_catalog({"profiles": {"a": {"optional_fields": ["X"]}}})
        assert catalog.get("a").fields == ("X",)

    def test_identifiers_are_lowercased(self) -> None:
        catalog = build_catalog({"profiles": {"Sysmon_One": {}}})
        assert catalog.get("sysmon_one") is not None

    def test_the_sources_list_shape_is_accepted(self) -> None:
        catalog = build_catalog({"sources": [{"telemetry_id": "a", "product": "windows"}]})
        assert catalog.get("a").product == "windows"

    def test_the_sources_list_accepts_a_bare_id_key(self) -> None:
        catalog = build_catalog({"sources": [{"id": "a"}]})
        assert catalog.get("a") is not None

    def test_a_document_with_neither_shape_is_refused(self) -> None:
        with pytest.raises(TelemetryError, match="'profiles' or 'sources'"):
            build_catalog({"schema_version": "1.0"})

    def test_profiles_must_be_an_object(self) -> None:
        with pytest.raises(TelemetryError, match="must be an object"):
            build_catalog({"profiles": ["a"]})

    def test_a_profile_entry_must_be_an_object(self) -> None:
        with pytest.raises(TelemetryError, match="must be an object"):
            build_catalog({"profiles": {"a": "not an object"}})

    def test_sources_must_be_a_list(self) -> None:
        with pytest.raises(TelemetryError, match="must be a list"):
            build_catalog({"sources": {"a": {}}})

    def test_a_source_entry_must_be_an_object(self) -> None:
        with pytest.raises(TelemetryError, match="must be an object"):
            build_catalog({"sources": ["a"]})

    def test_a_source_entry_needs_an_identifier(self) -> None:
        with pytest.raises(TelemetryError, match="'telemetry_id' is required"):
            build_catalog({"sources": [{"name": "x"}]})

    def test_a_malformed_identifier_is_refused(self) -> None:
        with pytest.raises(TelemetryError, match="lowercase words"):
            build_catalog({"profiles": {"Bad Id!": {}}})

    def test_a_duplicate_identifier_is_refused(self) -> None:
        with pytest.raises(TelemetryError, match="duplicate telemetry_id"):
            build_catalog({"sources": [{"id": "a"}, {"id": "A"}]})

    def test_a_non_object_logsource_is_refused(self) -> None:
        with pytest.raises(TelemetryError, match="'logsource' must be an object"):
            build_catalog({"profiles": {"a": {"logsource": ["windows"]}}})

    def test_a_non_sequence_field_list_is_refused(self) -> None:
        with pytest.raises(TelemetryError, match="expected a string or a list"):
            build_catalog({"profiles": {"a": {"fields": 7}}})

    @pytest.mark.parametrize("identifier", ["sysmon", "sysmon_1", "win-security", "a1_b2-c3"])
    def test_accepted_identifier_shapes(self, identifier: str) -> None:
        assert TELEMETRY_ID_PATTERN.match(identifier)

    @pytest.mark.parametrize("identifier", ["Sysmon", "sysmon 1", "_sysmon", "sysmon_", "sys..mon"])
    def test_rejected_identifier_shapes(self, identifier: str) -> None:
        assert TELEMETRY_ID_PATTERN.match(identifier) is None


class TestCatalogLookup:
    def test_get_ignores_case(self) -> None:
        assert loaded().get("SYSMON_PROCESS_CREATION") is not None

    def test_get_of_an_unknown_id_is_none(self) -> None:
        assert loaded().get("nope") is None

    def test_resolve_finds_by_identifier(self) -> None:
        assert loaded().resolve("sysmon_process_creation") is not None

    def test_resolve_finds_by_required_log_name(self) -> None:
        assert loaded().resolve("Sysmon Operational log") is not None

    def test_resolve_by_log_name_ignores_case(self) -> None:
        assert loaded().resolve("sysmon operational LOG") is not None

    def test_resolve_of_an_unknown_reference_is_none(self) -> None:
        assert loaded().resolve("Splunk index") is None

    def test_for_logsource_matches_product_and_category(self) -> None:
        found = loaded().for_logsource("windows", "process_creation")
        assert len(found) == 1

    def test_for_logsource_ignores_unset_parts(self) -> None:
        assert len(loaded().for_logsource(None, None)) == 1

    def test_for_logsource_rejects_a_mismatch(self) -> None:
        assert loaded().for_logsource("linux", "process_creation") == ()

    def test_for_logsource_requires_a_value_when_asked(self) -> None:
        assert loaded().for_logsource("windows", "process_creation", "sysmon") == ()

    def test_to_dict_reports_the_source_count(self) -> None:
        assert loaded().to_dict()["source_count"] == 1

    def test_to_dict_reports_availability(self) -> None:
        assert loaded().to_dict()["available"] is True

    def test_an_unavailable_catalog_reports_its_error(self) -> None:
        catalog = TelemetryCatalog(available=False, load_error="missing")
        assert catalog.to_dict()["load_error"] == "missing"


class TestLoading:
    def test_the_real_catalog_loads(self, real_config: LabConfig) -> None:
        assert load_telemetry_catalog(real_config).available is True

    def test_the_real_catalog_has_sources(self, real_config: LabConfig) -> None:
        assert load_telemetry_catalog(real_config).sources

    def test_the_expected_filename_is_used(self) -> None:
        assert CATALOG_FILENAME == "telemetry-catalog.json"

    def test_an_absent_catalog_is_unavailable_not_fatal(self, tiny_config: LabConfig) -> None:
        target = tiny_config.config_dir / CATALOG_FILENAME
        if target.exists():
            target.unlink()
        assert load_telemetry_catalog(tiny_config).available is False

    def test_an_absent_catalog_records_why(self, tiny_config: LabConfig) -> None:
        target = tiny_config.config_dir / CATALOG_FILENAME
        if target.exists():
            target.unlink()
        assert load_telemetry_catalog(tiny_config).load_error

    def test_a_malformed_catalog_is_unavailable_not_fatal(self, tiny_config: LabConfig) -> None:
        write_json(tiny_config.config_dir / CATALOG_FILENAME, {"profiles": ["bad"]})
        catalog = load_telemetry_catalog(tiny_config)
        assert catalog.available is False
        assert "must be an object" in catalog.load_error

    def test_a_valid_catalog_on_disk_loads(self, tiny_config: LabConfig) -> None:
        write_json(tiny_config.config_dir / CATALOG_FILENAME, catalog_document())
        assert load_telemetry_catalog(tiny_config).get("sysmon_process_creation") is not None


class TestDetectionFieldNames:
    def test_a_plain_field_is_reported(self) -> None:
        rule = make_rule(detection={"selection": {"Image": "x"}, "condition": "selection"})
        assert detection_field_names(rule) == ("Image",)

    def test_a_modifier_suffix_is_stripped(self) -> None:
        rule = make_rule(detection={"selection": {"Image|endswith": "x"}, "condition": "selection"})
        assert detection_field_names(rule) == ("Image",)

    def test_chained_modifiers_are_stripped(self) -> None:
        rule = make_rule(
            detection={"selection": {"CommandLine|contains|all": ["a"]}, "condition": "selection"}
        )
        assert detection_field_names(rule) == ("CommandLine",)

    def test_the_condition_key_is_not_a_field(self) -> None:
        rule = make_rule(detection={"selection": {"Image": "x"}, "condition": "selection"})
        assert "condition" not in detection_field_names(rule)

    def test_fields_from_several_selections_are_collected(self) -> None:
        rule = make_rule(
            detection={
                "selection": {"Image": "x"},
                "filter": {"User": "y"},
                "condition": "selection and not filter",
            }
        )
        assert set(detection_field_names(rule)) == {"Image", "User"}

    def test_fields_inside_a_list_of_maps_are_collected(self) -> None:
        rule = make_rule(
            detection={
                "selection": [{"Image": "a"}, {"ParentImage": "b"}],
                "condition": "selection",
            }
        )
        assert set(detection_field_names(rule)) == {"Image", "ParentImage"}

    def test_duplicates_are_reported_once(self) -> None:
        rule = make_rule(
            detection={
                "selection": {"Image": "a"},
                "other": {"Image": "b"},
                "condition": "selection or other",
            }
        )
        assert detection_field_names(rule) == ("Image",)

    def test_keyword_lists_contribute_no_field_names(self) -> None:
        rule = make_rule(detection={"keywords": ["mimikatz"], "condition": "keywords"})
        assert detection_field_names(rule) == ()

    def test_the_order_of_first_appearance_is_kept(self) -> None:
        rule = make_rule(
            detection={"selection": {"B": 1, "A": 2}, "condition": "selection"},
        )
        assert detection_field_names(rule) == ("B", "A")


class TestValidateRequirements:
    def test_a_satisfied_requirement_produces_nothing(self) -> None:
        rule = make_rule(detection={"selection": {"Image": "x"}, "condition": "selection"})
        findings = validate_requirements(
            rule, ["sysmon_process_creation"], catalog=loaded(), path="s.json"
        )
        assert findings == []

    def test_an_empty_identifier_is_reported(self) -> None:
        findings = validate_requirements(make_rule(), ["  "], catalog=loaded(), path=None)
        assert [f.code for f in findings] == ["SDEL-TEL-001"]

    def test_an_unavailable_catalog_is_reported(self) -> None:
        findings = validate_requirements(
            make_rule(), ["sysmon"], catalog=TelemetryCatalog(available=False), path=None
        )
        assert [f.code for f in findings] == ["SDEL-TEL-002"]

    def test_the_unavailable_finding_suggests_the_catalog_file(self) -> None:
        findings = validate_requirements(
            make_rule(), ["sysmon"], catalog=TelemetryCatalog(available=False), path=None
        )
        assert CATALOG_FILENAME in findings[0].remediation

    def test_an_undefined_telemetry_id_is_reported(self) -> None:
        findings = validate_requirements(make_rule(), ["nope"], catalog=loaded(), path=None)
        assert [f.code for f in findings] == ["SDEL-TEL-003"]

    def test_an_undefined_telemetry_id_is_high_severity(self) -> None:
        findings = validate_requirements(make_rule(), ["nope"], catalog=loaded(), path=None)
        assert findings[0].severity is Severity.HIGH

    def test_no_requirements_produce_no_findings(self) -> None:
        assert validate_requirements(make_rule(), [], catalog=loaded(), path=None) == []

    def test_the_sidecar_path_is_carried_onto_findings(self) -> None:
        findings = validate_requirements(
            make_rule(), ["nope"], catalog=loaded(), path="metadata/rules/x.json"
        )
        assert findings[0].path == "metadata/rules/x.json"

    def test_an_undocumented_detection_field_is_reported(self) -> None:
        rule = make_rule(detection={"selection": {"Weird": "x"}, "condition": "selection"})
        findings = validate_requirements(
            rule, ["sysmon_process_creation"], catalog=loaded(), path=None
        )
        assert [f.code for f in findings] == ["SDEL-TEL-004"]

    def test_a_field_declared_by_the_sidecar_counts_as_documented(self) -> None:
        rule = make_rule(detection={"selection": {"Weird": "x"}, "condition": "selection"})
        findings = validate_requirements(
            rule,
            ["sysmon_process_creation"],
            catalog=loaded(),
            path=None,
            declared_fields=["Weird"],
        )
        assert findings == []

    def test_field_checks_are_case_insensitive(self) -> None:
        rule = make_rule(detection={"selection": {"IMAGE": "x"}, "condition": "selection"})
        findings = validate_requirements(
            rule, ["sysmon_process_creation"], catalog=loaded(), path=None
        )
        assert findings == []

    def test_field_checks_are_skipped_for_correlation_rules(self) -> None:
        rule = make_rule(
            detection={"selection": {"Weird": "x"}, "condition": "selection"},
            is_correlation=True,
        )
        findings = validate_requirements(
            rule, ["sysmon_process_creation"], catalog=loaded(), path=None
        )
        assert findings == []

    def test_an_undocumented_channel_is_reported(self) -> None:
        rule = make_rule(detection={"selection": {"Image": "x"}, "condition": "selection"})
        findings = validate_requirements(
            rule,
            ["sysmon_process_creation"],
            catalog=loaded(),
            path=None,
            declared_channels=["Security"],
        )
        assert [f.code for f in findings] == ["SDEL-TEL-006"]

    def test_an_undocumented_channel_is_low_severity(self) -> None:
        rule = make_rule(detection={"selection": {"Image": "x"}, "condition": "selection"})
        findings = validate_requirements(
            rule,
            ["sysmon_process_creation"],
            catalog=loaded(),
            path=None,
            declared_channels=["Security"],
        )
        assert findings[0].severity is Severity.LOW

    def test_a_documented_channel_passes(self) -> None:
        rule = make_rule(detection={"selection": {"Image": "x"}, "condition": "selection"})
        findings = validate_requirements(
            rule,
            ["sysmon_process_creation"],
            catalog=loaded(),
            path=None,
            declared_channels=["Microsoft-Windows-Sysmon/Operational"],
        )
        assert findings == []

    def test_a_source_without_channels_cannot_flag_one(self) -> None:
        catalog = build_catalog({"profiles": {"a": {"fields": ["Image"]}}})
        rule = make_rule(detection={"selection": {"Image": "x"}, "condition": "selection"})
        findings = validate_requirements(
            rule, ["a"], catalog=catalog, path=None, declared_channels=["Anything"]
        )
        assert [f for f in findings if f.code == "SDEL-TEL-006"] == []

    def test_a_disagreeing_logsource_is_reported(self) -> None:
        rule = make_rule(
            detection={"selection": {"Image": "x"}, "condition": "selection"},
            logsource=LogSource(product="linux", category="process_creation"),
        )
        findings = validate_requirements(
            rule, ["sysmon_process_creation"], catalog=loaded(), path=None
        )
        assert [f.code for f in findings] == ["SDEL-TEL-005"]

    def test_an_empty_logsource_is_not_checked(self) -> None:
        rule = make_rule(
            detection={"selection": {"Image": "x"}, "condition": "selection"},
            logsource=LogSource(),
        )
        findings = validate_requirements(
            rule, ["sysmon_process_creation"], catalog=loaded(), path=None
        )
        assert [f for f in findings if f.code == "SDEL-TEL-005"] == []

    def test_one_matching_source_is_enough(self) -> None:
        catalog = build_catalog(
            {
                "profiles": {
                    "linux_auth": {"product": "linux", "fields": ["Image"]},
                    "sysmon_process_creation": dict(SYSMON_PROFILE),
                }
            }
        )
        rule = make_rule(detection={"selection": {"Image": "x"}, "condition": "selection"})
        findings = validate_requirements(
            rule, ["linux_auth", "sysmon_process_creation"], catalog=catalog, path=None
        )
        assert [f for f in findings if f.code == "SDEL-TEL-005"] == []

    def test_every_finding_carries_the_gate_name(self) -> None:
        findings = validate_requirements(make_rule(), ["nope"], catalog=loaded(), path=None)
        assert all(f.gate == "telemetry_requirements_exist" for f in findings)

    def test_findings_name_the_rule(self) -> None:
        rule = make_rule(catalog_id="SDEL-XYZ-009")
        findings = validate_requirements(rule, ["nope"], catalog=loaded(), path=None)
        assert findings[0].subject == "SDEL-XYZ-009"


class TestValidateCatalog:
    def test_a_rule_without_a_sidecar_is_skipped(self) -> None:
        rules = RuleCatalog([make_rule(catalog_id="a")])
        assert validate_catalog(rules, MetadataSet(sidecars=()), loaded()) == []

    def test_a_matched_pair_is_validated(self) -> None:
        rule = make_rule(
            catalog_id="a", detection={"selection": {"Image": "x"}, "condition": "selection"}
        )
        sidecar = make_sidecar(
            catalog_id="a",
            telemetry_requirements=(TelemetryRequirement(telemetry_id="nope"),),
        )
        findings = validate_catalog(RuleCatalog([rule]), MetadataSet(sidecars=(sidecar,)), loaded())
        assert [f.code for f in findings] == ["SDEL-TEL-003"]

    def test_a_satisfied_pair_produces_nothing(self) -> None:
        rule = make_rule(
            catalog_id="a", detection={"selection": {"Image": "x"}, "condition": "selection"}
        )
        sidecar = make_sidecar(
            catalog_id="a",
            telemetry_requirements=(TelemetryRequirement(telemetry_id="sysmon_process_creation"),),
        )
        findings = validate_catalog(RuleCatalog([rule]), MetadataSet(sidecars=(sidecar,)), loaded())
        assert findings == []

    def test_findings_from_several_rules_are_concatenated(self) -> None:
        rules = RuleCatalog(
            [
                make_rule(catalog_id="a", rule_id="11111111-1111-4111-8111-111111111111"),
                make_rule(catalog_id="b", rule_id="22222222-2222-4222-8222-222222222222"),
            ]
        )
        sidecars = tuple(
            make_sidecar(
                catalog_id=name,
                telemetry_requirements=(TelemetryRequirement(telemetry_id="nope"),),
            )
            for name in ("a", "b")
        )
        findings = validate_catalog(rules, MetadataSet(sidecars=sidecars), loaded())
        assert len(findings) == 2


class TestTelemetryUsage:
    def test_an_empty_metadata_set_has_no_usage(self) -> None:
        assert telemetry_usage(MetadataSet(sidecars=())) == {}

    def test_one_requirement_is_counted(self) -> None:
        sidecar = make_sidecar(telemetry_requirements=(TelemetryRequirement(telemetry_id="a"),))
        assert telemetry_usage(MetadataSet(sidecars=(sidecar,))) == {"a": 1}

    def test_the_same_source_across_rules_accumulates(self) -> None:
        sidecars = tuple(
            make_sidecar(
                catalog_id=name,
                telemetry_requirements=(TelemetryRequirement(telemetry_id="a"),),
            )
            for name in ("x", "y")
        )
        assert telemetry_usage(MetadataSet(sidecars=sidecars)) == {"a": 2}

    def test_identifiers_are_normalised(self) -> None:
        sidecar = make_sidecar(telemetry_requirements=(TelemetryRequirement(telemetry_id=" A "),))
        assert telemetry_usage(MetadataSet(sidecars=(sidecar,))) == {"a": 1}

    def test_the_result_is_sorted(self) -> None:
        sidecar = make_sidecar(
            telemetry_requirements=(
                TelemetryRequirement(telemetry_id="z"),
                TelemetryRequirement(telemetry_id="a"),
            )
        )
        assert list(telemetry_usage(MetadataSet(sidecars=(sidecar,)))) == ["a", "z"]


class TestRealTelemetry:
    @pytest.fixture(scope="class")
    def catalog_path(self, project_root: Path) -> Path:
        return project_root / "config" / CATALOG_FILENAME

    def test_the_catalog_file_is_committed(self, project_root: Path) -> None:
        assert (project_root / "config" / CATALOG_FILENAME).is_file()

    def test_every_real_declaration_resolves(
        self, real_config: LabConfig, real_metadata: MetadataSet
    ) -> None:
        catalog = load_telemetry_catalog(real_config)
        unresolved = [
            requirement.telemetry_id
            for sidecar in real_metadata.sidecars
            for requirement in sidecar.telemetry_requirements
            if catalog.resolve(requirement.telemetry_id) is None
        ]
        assert unresolved == []

    def test_the_real_repository_has_no_telemetry_findings(
        self,
        real_config: LabConfig,
        real_catalog: RuleCatalog,
        real_metadata: MetadataSet,
    ) -> None:
        findings = validate_catalog(
            real_catalog, real_metadata, load_telemetry_catalog(real_config)
        )
        assert [f"{f.code} {f.subject}: {f.message}" for f in findings] == []

    def test_every_rule_depends_on_some_telemetry(self, real_metadata: MetadataSet) -> None:
        assert telemetry_usage(real_metadata)
