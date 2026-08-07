"""The vendored offline ATT&CK catalog: loading, indexing, and shape checks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.conftest import ATTACK_SUBSET, write_json

from sigma_detection_engineering_lab.attack_catalog import (
    OBJECT_KEYS,
    AttackCatalog,
    AttackObject,
    is_well_formed,
    load_attack_catalog,
    tactic_names_from_tags,
    technique_ids_from_tags,
)
from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.errors import AttackCatalogError


@pytest.fixture
def attack(tiny_config: LabConfig) -> AttackCatalog:
    return load_attack_catalog(tiny_config)


class TestAttackObject:
    def test_a_plain_object_is_active(self) -> None:
        assert AttackObject("T1059").is_active is True

    def test_a_deprecated_object_is_not_active(self) -> None:
        assert AttackObject("T1059", deprecated=True).is_active is False

    def test_a_revoked_object_is_not_active(self) -> None:
        assert AttackObject("T1059", revoked=True).is_active is False

    def test_serialisation_covers_every_field(self) -> None:
        payload = AttackObject("T1059", name="Command", object_type="techniques").to_dict()
        assert set(payload) == {
            "id",
            "name",
            "type",
            "shortname",
            "tactics",
            "deprecated",
            "revoked",
            "url",
        }

    def test_tactics_serialise_as_a_list(self) -> None:
        payload = AttackObject("T1059", tactics=("TA0002",)).to_dict()
        assert payload["tactics"] == ["TA0002"]


class TestLoading:
    def test_the_subset_loads(self, attack: AttackCatalog) -> None:
        assert attack.is_available is True

    def test_techniques_are_indexed(self, attack: AttackCatalog) -> None:
        assert attack.get_technique("T1204.002") is not None

    def test_technique_lookup_is_case_insensitive(self, attack: AttackCatalog) -> None:
        assert attack.get_technique("t1204.002") is not None

    def test_technique_lookup_trims_whitespace(self, attack: AttackCatalog) -> None:
        assert attack.get_technique("  T1204.002  ") is not None

    def test_an_unknown_technique_is_absent(self, attack: AttackCatalog) -> None:
        assert attack.get_technique("T9998") is None

    def test_tactics_are_indexed_by_id(self, attack: AttackCatalog) -> None:
        assert attack.get_tactic("TA0002") is not None

    def test_tactics_resolve_by_shortname(self, attack: AttackCatalog) -> None:
        assert attack.get_tactic("execution") is not None

    def test_tactics_resolve_by_hyphenated_name(self, attack: AttackCatalog) -> None:
        assert attack.get_tactic("credential-access") is not None

    def test_an_unknown_tactic_is_absent(self, attack: AttackCatalog) -> None:
        assert attack.get_tactic("nonsense") is None

    def test_deprecated_objects_are_marked(self, attack: AttackCatalog) -> None:
        assert attack.get_technique("T1999").is_active is False

    def test_the_attack_version_is_read(self, attack: AttackCatalog) -> None:
        assert attack.attack_version == "19.1"

    def test_the_domain_is_read(self, attack: AttackCatalog) -> None:
        assert attack.domain == "enterprise-attack"

    def test_the_source_file_is_recorded(self, attack: AttackCatalog) -> None:
        assert any("enterprise-attack-subset.json" in source for source in attack.sources)

    def test_the_object_count_sums_every_bucket(self, attack: AttackCatalog) -> None:
        assert attack.object_count == sum(len(attack.collection(key)) for key in OBJECT_KEYS)

    def test_no_load_errors_for_a_valid_subset(self, attack: AttackCatalog) -> None:
        assert attack.load_errors == ()

    def test_detection_strategies_load(self, attack: AttackCatalog) -> None:
        assert attack.get("detection_strategies", "DET0001") is not None

    def test_analytics_load(self, attack: AttackCatalog) -> None:
        assert attack.get("analytics", "AN0001") is not None

    def test_data_components_load(self, attack: AttackCatalog) -> None:
        assert attack.get("data_components", "DC0001") is not None


class TestLoadFailures:
    def test_a_missing_directory_yields_an_unavailable_catalog(
        self, tiny_config: LabConfig, tmp_path: Path
    ) -> None:
        catalog = load_attack_catalog(tiny_config, directory=tmp_path / "absent")
        assert catalog.is_available is False

    def test_a_missing_directory_records_the_reason(
        self, tiny_config: LabConfig, tmp_path: Path
    ) -> None:
        catalog = load_attack_catalog(tiny_config, directory=tmp_path / "absent")
        assert "does not exist" in catalog.load_errors[0][1]

    def test_invalid_json_becomes_a_load_error(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        (tiny_project / "data" / "attack" / "broken.json").write_text("{", encoding="utf-8")
        catalog = load_attack_catalog(tiny_config)
        assert any("invalid JSON" in message for _, message in catalog.load_errors)

    def test_a_broken_file_does_not_hide_a_good_one(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        (tiny_project / "data" / "attack" / "broken.json").write_text("{", encoding="utf-8")
        assert load_attack_catalog(tiny_config).is_available is True

    def test_a_scalar_root_is_a_load_error(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        (tiny_project / "data" / "attack" / "scalar.json").write_text('"text"', encoding="utf-8")
        catalog = load_attack_catalog(tiny_config)
        assert any("must be an object or a list" in message for _, message in catalog.load_errors)

    def test_a_bare_list_with_an_unhelpful_filename_is_an_error(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        (tiny_project / "data" / "attack" / "mystery.json").write_text("[]", encoding="utf-8")
        catalog = load_attack_catalog(tiny_config)
        assert any("bare list" in message for _, message in catalog.load_errors)

    def test_a_bare_list_named_for_its_type_is_merged(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        write_json(
            tiny_project / "data" / "attack" / "techniques.json",
            [{"id": "T1055", "name": "Process Injection"}],
        )
        assert load_attack_catalog(tiny_config).get_technique("T1055") is not None

    def test_a_non_list_object_section_is_an_error(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        write_json(tiny_project / "data" / "attack" / "bad.json", {"techniques": "T1055"})
        catalog = load_attack_catalog(tiny_config)
        assert any("must be a list" in message for _, message in catalog.load_errors)

    def test_an_entry_without_an_id_is_an_error(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        write_json(tiny_project / "data" / "attack" / "bad.json", {"techniques": [{"name": "x"}]})
        catalog = load_attack_catalog(tiny_config)
        assert any("has no 'id'" in message for _, message in catalog.load_errors)

    def test_a_numeric_entry_is_an_error(self, tiny_config: LabConfig, tiny_project: Path) -> None:
        write_json(tiny_project / "data" / "attack" / "bad.json", {"techniques": [7]})
        catalog = load_attack_catalog(tiny_config)
        assert any("must be a string or an object" in message for _, message in catalog.load_errors)

    def test_a_bare_string_entry_is_accepted(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        write_json(tiny_project / "data" / "attack" / "extra.json", {"techniques": ["T1055"]})
        assert load_attack_catalog(tiny_config).get_technique("T1055") is not None


class TestAlternateSchemas:
    def build(self, tiny_config: LabConfig, tiny_project: Path, payload: object) -> AttackCatalog:
        path = tiny_project / "data" / "attack" / "extra.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return load_attack_catalog(tiny_config)

    def test_the_attack_id_key_is_accepted(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        catalog = self.build(tiny_config, tiny_project, {"techniques": [{"attack_id": "T1055"}]})
        assert catalog.get_technique("T1055") is not None

    def test_the_external_id_key_is_accepted(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        catalog = self.build(tiny_config, tiny_project, {"techniques": [{"external_id": "T1055"}]})
        assert catalog.get_technique("T1055") is not None

    def test_kill_chain_phases_become_tactics(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        catalog = self.build(
            tiny_config,
            tiny_project,
            {"techniques": [{"id": "T1055", "kill_chain_phases": [{"phase_name": "execution"}]}]},
        )
        assert catalog.get_technique("T1055").tactics == ("execution",)

    def test_a_scalar_tactic_becomes_a_one_item_tuple(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        catalog = self.build(
            tiny_config, tiny_project, {"techniques": [{"id": "T1055", "tactics": "TA0002"}]}
        )
        assert catalog.get_technique("T1055").tactics == ("TA0002",)

    def test_the_mitre_shortname_key_is_accepted(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        catalog = self.build(
            tiny_config,
            tiny_project,
            {"tactics": [{"id": "TA0040", "x_mitre_shortname": "impact"}]},
        )
        assert catalog.get_tactic("impact") is not None

    def test_the_mitre_deprecated_flag_is_honoured(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        catalog = self.build(
            tiny_config,
            tiny_project,
            {"techniques": [{"id": "T1055", "x_mitre_deprecated": True}]},
        )
        assert catalog.get_technique("T1055").is_active is False

    def test_a_url_is_captured(self, tiny_config: LabConfig, tiny_project: Path) -> None:
        catalog = self.build(
            tiny_config,
            tiny_project,
            {"techniques": [{"id": "T1055", "url": "https://attack.mitre.org/techniques/T1055/"}]},
        )
        assert catalog.get_technique("T1055").url.endswith("/T1055/")


class TestCollectionAccess:
    def test_each_known_type_returns_a_mapping(self, attack: AttackCatalog) -> None:
        assert all(isinstance(attack.collection(key), dict) for key in OBJECT_KEYS)

    def test_an_unknown_type_is_refused(self, attack: AttackCatalog) -> None:
        with pytest.raises(AttackCatalogError, match="unknown ATT&CK object type"):
            attack.collection("mitigations")

    def test_get_dispatches_to_tactics(self, attack: AttackCatalog) -> None:
        assert attack.get("tactics", "execution") is not None

    def test_get_uppercases_identifiers(self, attack: AttackCatalog) -> None:
        assert attack.get("techniques", "t1204") is not None

    def test_get_returns_none_for_an_absent_object(self, attack: AttackCatalog) -> None:
        assert attack.get("analytics", "AN9999") is None


class TestParentTechniques:
    def test_a_sub_technique_has_a_parent(self, attack: AttackCatalog) -> None:
        assert attack.parent_technique("T1204.002") == "T1204"

    def test_a_base_technique_is_its_own_parent(self, attack: AttackCatalog) -> None:
        assert attack.parent_technique("T1204") == "T1204"

    def test_the_parent_is_uppercased(self, attack: AttackCatalog) -> None:
        assert attack.parent_technique("t1204.002") == "T1204"

    def test_whitespace_is_trimmed(self, attack: AttackCatalog) -> None:
        assert attack.parent_technique(" T1204.002 ") == "T1204"


class TestWellFormedness:
    @pytest.mark.parametrize("value", ["T1059", "T1059.001", "t1059", "T0001"])
    def test_valid_technique_shapes(self, value: str) -> None:
        assert is_well_formed("techniques", value) is True

    @pytest.mark.parametrize("value", ["T105", "T10599", "T1059.1", "TA0002", "1059", ""])
    def test_invalid_technique_shapes(self, value: str) -> None:
        assert is_well_formed("techniques", value) is False

    @pytest.mark.parametrize("value", ["TA0002", "execution", "credential-access"])
    def test_valid_tactic_shapes(self, value: str) -> None:
        assert is_well_formed("tactics", value) is True

    @pytest.mark.parametrize("value", ["Credential Access", "-leading", "trailing-", ""])
    def test_invalid_tactic_shapes(self, value: str) -> None:
        assert is_well_formed("tactics", value) is False

    def test_a_malformed_tactic_id_falls_back_to_the_shortname_shape(self) -> None:
        assert is_well_formed("tactics", "TA002") is True

    def test_detection_strategy_shape(self) -> None:
        assert is_well_formed("detection_strategies", "DET0001") is True
        assert is_well_formed("detection_strategies", "DET1") is False

    def test_analytic_shape(self) -> None:
        assert is_well_formed("analytics", "AN0001") is True
        assert is_well_formed("analytics", "ANALYTIC") is False

    def test_data_component_shape(self) -> None:
        assert is_well_formed("data_components", "DC0001") is True
        assert is_well_formed("data_components", "DC") is False

    def test_an_unknown_type_is_refused(self) -> None:
        with pytest.raises(AttackCatalogError):
            is_well_formed("mitigations", "M1234")

    def test_a_well_formed_identifier_can_still_be_absent(self, attack: AttackCatalog) -> None:
        assert is_well_formed("techniques", "T9998") is True
        assert attack.get_technique("T9998") is None


class TestTagExtraction:
    def test_a_technique_tag_is_extracted(self) -> None:
        assert technique_ids_from_tags(["attack.t1059"]) == ("T1059",)

    def test_a_sub_technique_tag_is_extracted(self) -> None:
        assert technique_ids_from_tags(["attack.t1059.001"]) == ("T1059.001",)

    def test_non_attack_tags_are_ignored(self) -> None:
        assert technique_ids_from_tags(["cve.2024-1234", "tlp.clear"]) == ()

    def test_tactic_tags_are_not_techniques(self) -> None:
        assert technique_ids_from_tags(["attack.execution"]) == ()

    def test_duplicates_are_collapsed(self) -> None:
        assert technique_ids_from_tags(["attack.t1059", "attack.T1059"]) == ("T1059",)

    def test_order_is_preserved(self) -> None:
        tags = ["attack.t1204", "attack.t1059"]
        assert technique_ids_from_tags(tags) == ("T1204", "T1059")

    def test_whitespace_is_tolerated(self) -> None:
        assert technique_ids_from_tags(["  attack.t1059  "]) == ("T1059",)

    def test_a_tactic_tag_is_extracted(self) -> None:
        assert tactic_names_from_tags(["attack.execution"]) == ("execution",)

    def test_underscores_become_hyphens(self) -> None:
        assert tactic_names_from_tags(["attack.credential_access"]) == ("credential-access",)

    def test_technique_tags_are_not_tactics(self) -> None:
        assert tactic_names_from_tags(["attack.t1059"]) == ()

    def test_tactic_duplicates_are_collapsed(self) -> None:
        assert tactic_names_from_tags(["attack.execution", "attack.execution"]) == ("execution",)

    def test_both_kinds_can_be_separated_from_one_list(self) -> None:
        tags = ["attack.execution", "attack.t1059.001", "tlp.clear"]
        assert technique_ids_from_tags(tags) == ("T1059.001",)
        assert tactic_names_from_tags(tags) == ("execution",)


class TestSerialisation:
    def test_the_summary_reports_availability(self, attack: AttackCatalog) -> None:
        assert attack.to_dict()["available"] is True

    def test_the_summary_counts_each_bucket(self, attack: AttackCatalog) -> None:
        assert set(attack.to_dict()["counts"]) == set(OBJECT_KEYS)

    def test_the_summary_lists_sources(self, attack: AttackCatalog) -> None:
        assert attack.to_dict()["sources"]

    def test_the_summary_lists_load_errors(self) -> None:
        catalog = AttackCatalog(load_errors=(("a.json", "boom"),))
        assert catalog.to_dict()["load_errors"] == [{"path": "a.json", "message": "boom"}]

    def test_an_empty_catalog_is_unavailable(self) -> None:
        assert AttackCatalog().to_dict()["available"] is False

    def test_the_summary_is_json_serialisable(self, attack: AttackCatalog) -> None:
        assert json.loads(json.dumps(attack.to_dict()))["object_count"] == attack.object_count


class TestRealAttackData:
    def test_the_real_subset_is_available(self, real_attack: AttackCatalog) -> None:
        assert real_attack.is_available is True

    def test_the_real_subset_loaded_cleanly(self, real_attack: AttackCatalog) -> None:
        assert real_attack.load_errors == ()

    def test_the_real_subset_declares_a_version(self, real_attack: AttackCatalog) -> None:
        assert real_attack.attack_version

    def test_every_real_technique_id_is_well_formed(self, real_attack: AttackCatalog) -> None:
        offenders = [key for key in real_attack.techniques if not is_well_formed("techniques", key)]
        assert offenders == []

    def test_every_real_tactic_id_is_well_formed(self, real_attack: AttackCatalog) -> None:
        offenders = [key for key in real_attack.tactics if not is_well_formed("tactics", key)]
        assert offenders == []

    def test_the_fixture_subset_mirrors_the_real_schema(self, attack: AttackCatalog) -> None:
        assert set(ATTACK_SUBSET) >= {"techniques", "tactics"}
        assert attack.is_available
