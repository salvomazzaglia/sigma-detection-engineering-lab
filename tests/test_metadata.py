"""Sidecar metadata: parsing, identity binding, and cross-checks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.conftest import SAMPLE_SIDECAR, make_rule, make_sidecar, write_json

from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.errors import MetadataError
from sigma_detection_engineering_lab.metadata_loader import (
    CATALOG_ID_PATTERN,
    KNOWN_SIDECAR_KEYS,
    MIN_HYPOTHESIS_LENGTH,
    MetadataSet,
    assign_catalog_ids,
    build_sidecar,
    load_metadata,
    load_sidecar_file,
    maturity_distribution,
    validate_metadata,
)
from sigma_detection_engineering_lab.models import TelemetryRequirement
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.statuses import Maturity


def sidecar_document(**overrides: Any) -> dict[str, Any]:
    document = dict(SAMPLE_SIDECAR)
    document.update(overrides)
    return document


def build(document: Any, *, name: str = "SDEL-TST-001") -> Any:
    return build_sidecar(
        document,
        path=Path(f"metadata/rules/{name}.json"),
        relative_path=f"metadata/rules/{name}.json",
    )


class TestSidecarParsing:
    def test_a_complete_sidecar_parses(self) -> None:
        assert build(sidecar_document()).catalog_id == "SDEL-TST-001"

    def test_the_rule_uuid_is_bound(self) -> None:
        assert build(sidecar_document()).rule_id == SAMPLE_SIDECAR["sigma_rule_id"]

    def test_the_legacy_rule_id_key_still_works(self) -> None:
        document = sidecar_document()
        document["rule_id"] = document.pop("sigma_rule_id")
        assert build(document).rule_id == SAMPLE_SIDECAR["sigma_rule_id"]

    def test_sigma_rule_id_wins_over_rule_id(self) -> None:
        document = sidecar_document(rule_id="99999999-9999-4999-8999-999999999999")
        assert build(document).rule_id == SAMPLE_SIDECAR["sigma_rule_id"]

    def test_catalog_id_is_required(self) -> None:
        document = sidecar_document()
        del document["catalog_id"]
        with pytest.raises(MetadataError, match="'catalog_id' is required"):
            build(document)

    def test_a_blank_catalog_id_is_refused(self) -> None:
        with pytest.raises(MetadataError, match="'catalog_id' is required"):
            build(sidecar_document(catalog_id="  "))

    def test_the_rule_uuid_is_required(self) -> None:
        document = sidecar_document()
        del document["sigma_rule_id"]
        with pytest.raises(MetadataError, match="sigma_rule_id"):
            build(document)

    def test_identifiers_are_stripped(self) -> None:
        sidecar = build(sidecar_document(catalog_id=" SDEL-TST-001 "))
        assert sidecar.catalog_id == "SDEL-TST-001"

    def test_unknown_keys_are_refused(self) -> None:
        with pytest.raises(MetadataError, match="unknown key"):
            build(sidecar_document(mystery_field=1))

    def test_the_error_names_the_unknown_key(self) -> None:
        with pytest.raises(MetadataError, match="mystery_field"):
            build(sidecar_document(mystery_field=1))

    def test_every_sample_key_is_recognised(self) -> None:
        assert set(SAMPLE_SIDECAR) <= KNOWN_SIDECAR_KEYS

    def test_maturity_is_parsed(self) -> None:
        assert build(sidecar_document()).maturity is Maturity.EXPERIMENTAL

    def test_an_unknown_maturity_is_refused(self) -> None:
        with pytest.raises(MetadataError):
            build(sidecar_document(maturity="battle-hardened"))

    def test_the_raw_document_is_retained(self) -> None:
        assert build(sidecar_document()).raw["platform"] == "windows"

    def test_the_relative_path_is_recorded(self) -> None:
        assert build(sidecar_document()).relative_path.endswith("SDEL-TST-001.json")


class TestStringLists:
    def test_a_bare_string_becomes_a_one_item_tuple(self) -> None:
        assert build(sidecar_document(required_fields="Image")).required_fields == ("Image",)

    def test_a_list_is_preserved(self) -> None:
        sidecar = build(sidecar_document(required_fields=["Image", "CommandLine"]))
        assert sidecar.required_fields == ("Image", "CommandLine")

    def test_a_missing_list_is_empty(self) -> None:
        document = sidecar_document()
        del document["optional_fields"]
        assert build(document).optional_fields == ()

    def test_a_mapping_where_a_list_belongs_is_refused(self) -> None:
        with pytest.raises(MetadataError, match="required_fields"):
            build(sidecar_document(required_fields={"a": 1}))

    def test_required_channels_are_captured(self) -> None:
        sidecar = build(sidecar_document())
        assert sidecar.required_channels == ("Microsoft-Windows-Sysmon/Operational",)

    def test_supported_backends_are_captured(self) -> None:
        assert build(sidecar_document()).supported_backends == ("splunk",)


class TestTelemetryRequirements:
    def test_requirements_are_derived_from_required_logs(self) -> None:
        sidecar = build(sidecar_document())
        assert [item.telemetry_id for item in sidecar.telemetry_requirements] == [
            "Windows process creation telemetry"
        ]

    def test_explicit_string_requirements_are_accepted(self) -> None:
        sidecar = build(sidecar_document(telemetry_requirements=["sysmon_1"]))
        assert sidecar.telemetry_requirements[0].telemetry_id == "sysmon_1"

    def test_explicit_object_requirements_are_accepted(self) -> None:
        sidecar = build(
            sidecar_document(
                telemetry_requirements=[
                    {
                        "telemetry_id": "sysmon_1",
                        "description": "Process creation",
                        "required_fields": ["Image"],
                        "notes": "Synthetic only.",
                    }
                ]
            )
        )
        requirement = sidecar.telemetry_requirements[0]
        assert requirement.description == "Process creation"
        assert requirement.required_fields == ("Image",)
        assert requirement.notes == "Synthetic only."

    def test_the_id_key_is_an_accepted_alias(self) -> None:
        sidecar = build(sidecar_document(telemetry_requirements=[{"id": "sysmon_1"}]))
        assert sidecar.telemetry_requirements[0].telemetry_id == "sysmon_1"

    def test_an_object_without_an_id_is_refused(self) -> None:
        with pytest.raises(MetadataError, match="'telemetry_id' is required"):
            build(sidecar_document(telemetry_requirements=[{"description": "x"}]))

    def test_a_scalar_entry_that_is_not_a_string_is_refused(self) -> None:
        with pytest.raises(MetadataError, match="must be a string or an object"):
            build(sidecar_document(telemetry_requirements=[7]))

    def test_a_string_instead_of_a_list_is_refused(self) -> None:
        with pytest.raises(MetadataError, match="must be a list"):
            build(sidecar_document(telemetry_requirements="sysmon_1"))

    def test_explicit_requirements_win_over_derived_ones(self) -> None:
        sidecar = build(
            sidecar_document(
                required_logs=["A", "B"],
                telemetry_requirements=["only_this"],
            )
        )
        assert len(sidecar.telemetry_requirements) == 1

    def test_a_sidecar_with_no_telemetry_has_none(self) -> None:
        document = sidecar_document()
        del document["required_logs"]
        assert build(document).telemetry_requirements == ()


class TestNumericAndBooleanFields:
    def test_minimum_test_counts_are_read(self) -> None:
        sidecar = build(sidecar_document())
        assert sidecar.minimum_positive_tests == 1
        assert sidecar.minimum_negative_tests == 1

    def test_a_missing_count_defaults_to_zero(self) -> None:
        document = sidecar_document()
        del document["minimum_positive_tests"]
        assert build(document).minimum_positive_tests == 0

    def test_a_negative_count_is_refused(self) -> None:
        with pytest.raises(MetadataError, match="must not be negative"):
            build(sidecar_document(minimum_positive_tests=-1))

    def test_a_non_integer_count_is_refused(self) -> None:
        with pytest.raises(MetadataError, match="must be an integer"):
            build(sidecar_document(minimum_positive_tests="two"))

    def test_a_boolean_count_is_refused(self) -> None:
        with pytest.raises(MetadataError, match="must be an integer"):
            build(sidecar_document(minimum_positive_tests=True))

    def test_the_synthetic_marker_defaults_to_true(self) -> None:
        document = sidecar_document()
        del document["synthetic_fixtures_only"]
        assert build(document).synthetic_only is True

    def test_the_synthetic_marker_can_be_set_false(self) -> None:
        assert build(sidecar_document(synthetic_fixtures_only=False)).synthetic_only is False

    def test_a_non_boolean_synthetic_marker_is_refused(self) -> None:
        with pytest.raises(MetadataError, match="must be a boolean"):
            build(sidecar_document(synthetic_fixtures_only="yes"))

    def test_the_synthetic_only_alias_is_accepted(self) -> None:
        document = sidecar_document()
        del document["synthetic_fixtures_only"]
        document["synthetic_only"] = False
        assert build(document).synthetic_only is False


class TestAlternateKeys:
    def test_expected_collection_gaps_fill_known_limitations(self) -> None:
        sidecar = build(sidecar_document(expected_collection_gaps=["No EDR"]))
        assert sidecar.known_limitations == ("No EDR",)

    def test_known_limitations_win_over_collection_gaps(self) -> None:
        sidecar = build(
            sidecar_document(known_limitations=["Primary"], expected_collection_gaps=["Fallback"])
        )
        assert sidecar.known_limitations == ("Primary",)

    def test_test_strategy_fills_validation_notes(self) -> None:
        assert build(sidecar_document(test_strategy="Synthetic only")).validation_notes == (
            "Synthetic only"
        )

    def test_validation_notes_win_over_test_strategy(self) -> None:
        sidecar = build(sidecar_document(validation_notes="Primary", test_strategy="Fallback"))
        assert sidecar.validation_notes == "Primary"

    def test_unsupported_backend_reasons_must_be_an_object(self) -> None:
        with pytest.raises(MetadataError, match="must be an object"):
            build(sidecar_document(unsupported_backend_reasons=["splunk"]))

    def test_unsupported_backend_reasons_are_stringified(self) -> None:
        sidecar = build(sidecar_document(unsupported_backend_reasons={"qradar": "no backend"}))
        assert sidecar.unsupported_backend_reasons == {"qradar": "no backend"}


class TestAttackMappingExtraction:
    def test_techniques_come_from_the_flat_keys(self) -> None:
        assert build(sidecar_document()).attack_mapping.techniques == ("T1204.002",)

    def test_tactics_come_from_the_flat_keys(self) -> None:
        assert build(sidecar_document()).attack_mapping.tactics == ("TA0002",)

    def test_an_explicit_attack_mapping_object_is_used(self) -> None:
        sidecar = build(
            sidecar_document(attack_mapping={"techniques": ["T1003.001"], "tactics": ["TA0006"]})
        )
        assert sidecar.attack_mapping.techniques == ("T1003.001",)

    def test_a_non_object_attack_mapping_is_refused(self) -> None:
        with pytest.raises(MetadataError, match="'attack_mapping' must be an object"):
            build(sidecar_document(attack_mapping=["T1204"]))


class TestLoadingFromDisk:
    def test_a_json_sidecar_loads(self, tiny_config: LabConfig, tiny_project: Path) -> None:
        path = tiny_project / "metadata" / "rules" / "SDEL-TST-001.json"
        assert load_sidecar_file(path, config=tiny_config).catalog_id == "SDEL-TST-001"

    def test_a_yaml_sidecar_loads(self, tiny_config: LabConfig, tiny_project: Path) -> None:
        path = tiny_project / "metadata" / "rules" / "SDEL-TST-002.yml"
        path.write_text(json.dumps(sidecar_document(catalog_id="SDEL-TST-002")), encoding="utf-8")
        assert load_sidecar_file(path, config=tiny_config).catalog_id == "SDEL-TST-002"

    def test_invalid_json_is_reported(self, tiny_config: LabConfig, tiny_project: Path) -> None:
        path = tiny_project / "metadata" / "rules" / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(MetadataError, match="invalid JSON"):
            load_sidecar_file(path, config=tiny_config)

    def test_a_json_array_root_is_refused(self, tiny_config: LabConfig, tiny_project: Path) -> None:
        path = tiny_project / "metadata" / "rules" / "array.json"
        path.write_text("[]", encoding="utf-8")
        with pytest.raises(MetadataError, match="must be an object"):
            load_sidecar_file(path, config=tiny_config)

    def test_the_directory_loads_every_sidecar(self, tiny_config: LabConfig) -> None:
        assert len(load_metadata(tiny_config).sidecars) == 1

    def test_a_missing_directory_yields_an_empty_set(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        assert load_metadata(tiny_config, directory=tiny_project / "absent").sidecars == ()

    def test_a_broken_sidecar_is_collected_as_a_failure(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        (tiny_project / "metadata" / "rules" / "broken.json").write_text("{", encoding="utf-8")
        metadata = load_metadata(tiny_config)
        assert len(metadata.sidecars) == 1
        assert len(metadata.failures) == 1

    def test_sidecars_are_sorted_by_catalog_id(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        for catalog_id in ("SDEL-TST-009", "SDEL-TST-002"):
            write_json(
                tiny_project / "metadata" / "rules" / f"{catalog_id}.json",
                sidecar_document(catalog_id=catalog_id),
            )
        ids = [sidecar.catalog_id for sidecar in load_metadata(tiny_config).sidecars]
        assert ids == sorted(ids)


class TestMetadataSet:
    def test_indexing_by_catalog_id(self) -> None:
        metadata = MetadataSet(sidecars=(make_sidecar("SDEL-TST-001"),))
        assert "SDEL-TST-001" in metadata.by_catalog_id()

    def test_indexing_by_rule_id_lowercases(self) -> None:
        metadata = MetadataSet(sidecars=(make_sidecar(rule_id="AAAA-BBBB"),))
        assert "aaaa-bbbb" in metadata.by_rule_id()

    def test_a_sidecar_without_a_rule_id_is_not_indexed(self) -> None:
        metadata = MetadataSet(sidecars=(make_sidecar(rule_id="  "),))
        assert metadata.by_rule_id() == {}

    def test_get_returns_none_for_an_unknown_id(self) -> None:
        assert MetadataSet().get("nope") is None

    def test_the_summary_counts_sidecars_and_failures(self) -> None:
        metadata = MetadataSet(sidecars=(make_sidecar(),), failures=(("a.json", "boom"),))
        payload = metadata.to_dict()
        assert payload["sidecar_count"] == 1
        assert payload["failure_count"] == 1

    def test_the_summary_lists_failures(self) -> None:
        metadata = MetadataSet(failures=(("a.json", "boom"),))
        assert metadata.to_dict()["failures"] == [{"path": "a.json", "message": "boom"}]


class TestCatalogIdAssignment:
    def test_a_claimed_rule_takes_the_sidecar_identifier(self) -> None:
        rule = make_rule("filename_stem", rule_id="uuid-1")
        metadata = MetadataSet(sidecars=(make_sidecar("SDEL-WIN-001", rule_id="uuid-1"),))
        rules, findings = assign_catalog_ids([rule], metadata)
        assert rules[0].catalog_id == "SDEL-WIN-001"
        assert findings == []

    def test_matching_is_case_insensitive(self) -> None:
        rule = make_rule("stem", rule_id="UUID-1")
        metadata = MetadataSet(sidecars=(make_sidecar("SDEL-WIN-001", rule_id="uuid-1"),))
        rules, _ = assign_catalog_ids([rule], metadata)
        assert rules[0].catalog_id == "SDEL-WIN-001"

    def test_an_unclaimed_rule_keeps_its_provisional_identifier(self) -> None:
        rule = make_rule("filename_stem", rule_id="uuid-9")
        rules, findings = assign_catalog_ids([rule], MetadataSet())
        assert rules[0].catalog_id == "filename_stem"
        assert findings == []

    def test_a_rule_without_a_uuid_is_reported(self) -> None:
        rules, findings = assign_catalog_ids([make_rule("stem", rule_id="")], MetadataSet())
        assert [finding.code for finding in findings] == ["SDEL-MET-011"]
        assert rules[0].catalog_id == "stem"

    def test_two_rules_claimed_by_one_identifier_are_reported(self) -> None:
        metadata = MetadataSet(
            sidecars=(
                make_sidecar("SDEL-WIN-001", rule_id="uuid-1"),
                make_sidecar("SDEL-WIN-001", rule_id="uuid-2"),
            )
        )
        rules = [make_rule("a", rule_id="uuid-1"), make_rule("b", rule_id="uuid-2")]
        _, findings = assign_catalog_ids(rules, metadata)
        assert [finding.code for finding in findings] == ["SDEL-MET-013"]

    def test_results_are_sorted_by_the_new_identifier(self) -> None:
        metadata = MetadataSet(
            sidecars=(
                make_sidecar("SDEL-WIN-002", rule_id="uuid-1"),
                make_sidecar("SDEL-WIN-001", rule_id="uuid-2"),
            )
        )
        rules = [make_rule("a", rule_id="uuid-1"), make_rule("b", rule_id="uuid-2")]
        assigned, _ = assign_catalog_ids(rules, metadata)
        assert [rule.catalog_id for rule in assigned] == ["SDEL-WIN-001", "SDEL-WIN-002"]

    def test_assignment_does_not_mutate_the_input_rule(self) -> None:
        rule = make_rule("stem", rule_id="uuid-1")
        metadata = MetadataSet(sidecars=(make_sidecar("SDEL-WIN-001", rule_id="uuid-1"),))
        assign_catalog_ids([rule], metadata)
        assert rule.catalog_id == "stem"


class TestCatalogIdPattern:
    @pytest.mark.parametrize("value", ["SDEL-WIN-001", "SDEL-LNX-999", "SDEL-CLOUD-010"])
    def test_conforming_identifiers_match(self, value: str) -> None:
        expected = len(value.split("-")[1]) <= 4
        assert bool(CATALOG_ID_PATTERN.match(value)) is expected

    @pytest.mark.parametrize(
        "value",
        ["sdel-win-001", "SDEL-W-001", "SDEL-WIN-1", "SDEL-WIN-0001", "WIN-001", "SDEL-WIN"],
    )
    def test_nonconforming_identifiers_do_not_match(self, value: str) -> None:
        assert CATALOG_ID_PATTERN.match(value) is None


class TestValidation:
    def test_a_matched_pair_produces_no_findings(self, tiny_config: LabConfig) -> None:
        sidecar = make_sidecar(
            "SDEL-TST-001",
            rule_id="uuid-1",
            telemetry_requirements=(TelemetryRequirement(telemetry_id="sysmon_1"),),
        )
        catalog = RuleCatalog([make_rule("SDEL-TST-001", rule_id="uuid-1")])
        metadata = MetadataSet(sidecars=(sidecar,))
        assert validate_metadata(metadata, catalog, config=tiny_config) == []

    def test_a_missing_sidecar_is_reported(self, tiny_config: LabConfig) -> None:
        catalog = RuleCatalog([make_rule("SDEL-TST-001")])
        findings = validate_metadata(MetadataSet(), catalog, config=tiny_config)
        assert [finding.code for finding in findings] == ["SDEL-MET-002"]

    def test_a_load_failure_is_reported(self, tiny_config: LabConfig) -> None:
        metadata = MetadataSet(failures=(("metadata/rules/x.json", "boom"),))
        findings = validate_metadata(metadata, RuleCatalog([]), config=tiny_config)
        assert findings[0].code == "SDEL-MET-001"

    def test_a_uuid_mismatch_is_reported(self, tiny_config: LabConfig) -> None:
        metadata = MetadataSet(sidecars=(make_sidecar("SDEL-TST-001", rule_id="uuid-other"),))
        catalog = RuleCatalog([make_rule("SDEL-TST-001", rule_id="uuid-1")])
        codes = {f.code for f in validate_metadata(metadata, catalog, config=tiny_config)}
        assert "SDEL-MET-003" in codes

    def test_a_filename_mismatch_is_reported(self, tiny_config: LabConfig) -> None:
        sidecar = make_sidecar(
            "SDEL-TST-001", rule_id="uuid-1", relative_path="metadata/rules/wrong-name.json"
        )
        catalog = RuleCatalog([make_rule("SDEL-TST-001", rule_id="uuid-1")])
        codes = {
            f.code
            for f in validate_metadata(
                MetadataSet(sidecars=(sidecar,)), catalog, config=tiny_config
            )
        }
        assert "SDEL-MET-004" in codes

    def test_a_disallowed_maturity_is_reported(self, tiny_config: LabConfig) -> None:
        sidecar = make_sidecar(
            "SDEL-TST-001", rule_id="uuid-1", maturity=Maturity.PRODUCTION_OBSERVED
        )
        catalog = RuleCatalog([make_rule("SDEL-TST-001", rule_id="uuid-1")])
        codes = {
            f.code
            for f in validate_metadata(
                MetadataSet(sidecars=(sidecar,)), catalog, config=tiny_config
            )
        }
        assert "SDEL-MET-005" in codes

    def test_a_missing_hypothesis_is_reported(self, tiny_config: LabConfig) -> None:
        sidecar = make_sidecar("SDEL-TST-001", rule_id="uuid-1", detection_hypothesis="")
        catalog = RuleCatalog([make_rule("SDEL-TST-001", rule_id="uuid-1")])
        codes = {
            f.code
            for f in validate_metadata(
                MetadataSet(sidecars=(sidecar,)), catalog, config=tiny_config
            )
        }
        assert "SDEL-MET-006" in codes

    def test_a_thin_hypothesis_is_reported(self, tiny_config: LabConfig) -> None:
        sidecar = make_sidecar("SDEL-TST-001", rule_id="uuid-1", detection_hypothesis="short")
        catalog = RuleCatalog([make_rule("SDEL-TST-001", rule_id="uuid-1")])
        codes = {
            f.code
            for f in validate_metadata(
                MetadataSet(sidecars=(sidecar,)), catalog, config=tiny_config
            )
        }
        assert "SDEL-MET-007" in codes

    def test_a_hypothesis_at_the_threshold_passes(self, tiny_config: LabConfig) -> None:
        sidecar = make_sidecar(
            "SDEL-TST-001", rule_id="uuid-1", detection_hypothesis="x" * MIN_HYPOTHESIS_LENGTH
        )
        catalog = RuleCatalog([make_rule("SDEL-TST-001", rule_id="uuid-1")])
        codes = {
            f.code
            for f in validate_metadata(
                MetadataSet(sidecars=(sidecar,)), catalog, config=tiny_config
            )
        }
        assert "SDEL-MET-007" not in codes

    def test_missing_telemetry_is_reported(self, tiny_config: LabConfig) -> None:
        sidecar = make_sidecar("SDEL-TST-001", rule_id="uuid-1")
        catalog = RuleCatalog([make_rule("SDEL-TST-001", rule_id="uuid-1")])
        codes = {
            f.code
            for f in validate_metadata(
                MetadataSet(sidecars=(sidecar,)), catalog, config=tiny_config
            )
        }
        assert "SDEL-MET-008" in codes

    def test_a_non_synthetic_sidecar_is_reported(self, tiny_config: LabConfig) -> None:
        sidecar = make_sidecar("SDEL-TST-001", rule_id="uuid-1", synthetic_only=False)
        catalog = RuleCatalog([make_rule("SDEL-TST-001", rule_id="uuid-1")])
        codes = {
            f.code
            for f in validate_metadata(
                MetadataSet(sidecars=(sidecar,)), catalog, config=tiny_config
            )
        }
        assert "SDEL-MET-009" in codes

    def test_an_orphan_sidecar_is_reported(self, tiny_config: LabConfig) -> None:
        metadata = MetadataSet(sidecars=(make_sidecar("SDEL-TST-001"),))
        codes = {f.code for f in validate_metadata(metadata, RuleCatalog([]), config=tiny_config)}
        assert "SDEL-MET-010" in codes

    def test_a_malformed_catalog_id_is_reported(self, tiny_config: LabConfig) -> None:
        metadata = MetadataSet(sidecars=(make_sidecar("not-an-id", rule_id="uuid-1"),))
        catalog = RuleCatalog([make_rule("not-an-id", rule_id="uuid-1")])
        codes = {f.code for f in validate_metadata(metadata, catalog, config=tiny_config)}
        assert "SDEL-MET-011" in codes

    def test_every_finding_names_a_gate(self, tiny_config: LabConfig) -> None:
        catalog = RuleCatalog([make_rule("SDEL-TST-001")])
        findings = validate_metadata(MetadataSet(), catalog, config=tiny_config)
        assert all(finding.gate for finding in findings)

    def test_every_finding_is_categorised_as_metadata(self, tiny_config: LabConfig) -> None:
        catalog = RuleCatalog([make_rule("SDEL-TST-001")])
        findings = validate_metadata(MetadataSet(), catalog, config=tiny_config)
        assert all(str(finding.category) == "metadata" for finding in findings)


class TestMaturityDistribution:
    def test_an_empty_set_has_no_entries(self) -> None:
        assert maturity_distribution(MetadataSet()) == {}

    def test_levels_with_no_members_are_omitted(self) -> None:
        metadata = MetadataSet(sidecars=(make_sidecar(maturity=Maturity.EXPERIMENTAL),))
        assert set(maturity_distribution(metadata)) == {"experimental"}

    def test_counts_accumulate(self) -> None:
        metadata = MetadataSet(
            sidecars=(
                make_sidecar("a", maturity=Maturity.EXPERIMENTAL),
                make_sidecar("b", maturity=Maturity.EXPERIMENTAL),
            )
        )
        assert maturity_distribution(metadata)["experimental"] == 2

    def test_the_total_matches_the_sidecar_count(self, real_metadata: MetadataSet) -> None:
        assert sum(maturity_distribution(real_metadata).values()) == len(real_metadata.sidecars)


class TestRealMetadata:
    def test_every_real_sidecar_loaded(self, real_metadata: MetadataSet) -> None:
        assert real_metadata.failures == ()

    def test_the_real_project_has_sidecars(self, real_metadata: MetadataSet) -> None:
        assert len(real_metadata.sidecars) > 0

    def test_every_real_catalog_id_conforms(self, real_metadata: MetadataSet) -> None:
        offenders = [
            sidecar.catalog_id
            for sidecar in real_metadata.sidecars
            if not CATALOG_ID_PATTERN.match(sidecar.catalog_id)
        ]
        assert offenders == []

    def test_every_real_sidecar_is_synthetic_only(self, real_metadata: MetadataSet) -> None:
        assert all(sidecar.synthetic_only for sidecar in real_metadata.sidecars)

    def test_every_real_sidecar_has_a_substantial_hypothesis(
        self, real_metadata: MetadataSet
    ) -> None:
        offenders = [
            sidecar.catalog_id
            for sidecar in real_metadata.sidecars
            if len(sidecar.detection_hypothesis) < MIN_HYPOTHESIS_LENGTH
        ]
        assert offenders == []

    def test_real_catalog_ids_are_unique(self, real_metadata: MetadataSet) -> None:
        ids = [sidecar.catalog_id for sidecar in real_metadata.sidecars]
        assert len(set(ids)) == len(ids)

    def test_real_rule_uuids_are_unique(self, real_metadata: MetadataSet) -> None:
        ids = [sidecar.rule_id.lower() for sidecar in real_metadata.sidecars]
        assert len(set(ids)) == len(ids)

    def test_the_real_catalog_and_metadata_agree(
        self, real_catalog: RuleCatalog, real_metadata: MetadataSet
    ) -> None:
        assert set(real_catalog.catalog_ids) <= set(real_metadata.by_catalog_id())
