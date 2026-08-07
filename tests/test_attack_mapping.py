"""ATT&CK mapping validation: invented identifiers, drift, and honest gaps."""

from __future__ import annotations

import pytest
from tests.conftest import make_rule, make_sidecar

from sigma_detection_engineering_lab.attack_catalog import AttackCatalog, load_attack_catalog
from sigma_detection_engineering_lab.attack_mapping import (
    MIN_REASON_LENGTH,
    mapped_tactics,
    mapped_techniques,
    validate_catalog,
    validate_identifiers,
    validate_mapping,
    validate_rule_tags,
    validate_tag_sidecar_agreement,
)
from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.metadata_loader import MetadataSet
from sigma_detection_engineering_lab.models import AttackMapping
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.severities import Severity


@pytest.fixture
def attack(tiny_config: LabConfig) -> AttackCatalog:
    return load_attack_catalog(tiny_config)


def codes(findings: list) -> set[str]:
    return {finding.code for finding in findings}


class TestIdentifierValidation:
    def test_a_known_technique_passes(self, attack: AttackCatalog) -> None:
        findings = validate_identifiers(
            ["T1204.002"], "techniques", catalog=attack, subject="R", path=None
        )
        assert findings == []

    def test_an_empty_identifier_is_reported(self, attack: AttackCatalog) -> None:
        findings = validate_identifiers(
            ["  "], "techniques", catalog=attack, subject="R", path=None
        )
        assert codes(findings) == {"SDEL-ATT-001"}

    def test_a_duplicate_identifier_is_reported(self, attack: AttackCatalog) -> None:
        findings = validate_identifiers(
            ["T1204", "t1204"], "techniques", catalog=attack, subject="R", path=None
        )
        assert codes(findings) == {"SDEL-ATT-002"}

    def test_a_duplicate_is_only_low_severity(self, attack: AttackCatalog) -> None:
        findings = validate_identifiers(
            ["T1204", "T1204"], "techniques", catalog=attack, subject="R", path=None
        )
        assert findings[0].severity is Severity.LOW

    def test_a_malformed_identifier_is_reported(self, attack: AttackCatalog) -> None:
        findings = validate_identifiers(
            ["TECHNIQUE-1"], "techniques", catalog=attack, subject="R", path=None
        )
        assert codes(findings) == {"SDEL-ATT-003"}

    def test_an_invented_identifier_is_critical(self, attack: AttackCatalog) -> None:
        findings = validate_identifiers(
            ["T9998"], "techniques", catalog=attack, subject="R", path=None
        )
        assert findings[0].code == "SDEL-ATT-005"
        assert findings[0].severity is Severity.CRITICAL

    def test_an_invented_identifier_explains_the_harm(self, attack: AttackCatalog) -> None:
        findings = validate_identifiers(
            ["T9998"], "techniques", catalog=attack, subject="R", path=None
        )
        assert "fabricates coverage" in findings[0].message

    def test_a_deprecated_identifier_is_reported(self, attack: AttackCatalog) -> None:
        findings = validate_identifiers(
            ["T1999"], "techniques", catalog=attack, subject="R", path=None
        )
        assert codes(findings) == {"SDEL-ATT-006"}

    def test_an_unavailable_catalog_reports_unverifiability(self) -> None:
        findings = validate_identifiers(
            ["T1204"], "techniques", catalog=AttackCatalog(), subject="R", path=None
        )
        assert codes(findings) == {"SDEL-ATT-004"}

    def test_an_unavailable_catalog_does_not_claim_the_id_is_invented(self) -> None:
        findings = validate_identifiers(
            ["T1204"], "techniques", catalog=AttackCatalog(), subject="R", path=None
        )
        assert findings[0].severity is Severity.MEDIUM

    def test_a_malformed_identifier_short_circuits_existence(self, attack: AttackCatalog) -> None:
        findings = validate_identifiers(
            ["nonsense id"], "techniques", catalog=attack, subject="R", path=None
        )
        assert len(findings) == 1

    def test_known_tactics_pass(self, attack: AttackCatalog) -> None:
        assert (
            validate_identifiers(["TA0002"], "tactics", catalog=attack, subject="R", path=None)
            == []
        )

    def test_a_tactic_shortname_passes(self, attack: AttackCatalog) -> None:
        assert (
            validate_identifiers(["execution"], "tactics", catalog=attack, subject="R", path=None)
            == []
        )

    def test_an_invented_tactic_is_reported(self, attack: AttackCatalog) -> None:
        findings = validate_identifiers(
            ["TA9999"], "tactics", catalog=attack, subject="R", path=None
        )
        assert codes(findings) == {"SDEL-ATT-005"}

    def test_detection_strategies_are_validated(self, attack: AttackCatalog) -> None:
        assert (
            validate_identifiers(
                ["DET0001"], "detection_strategies", catalog=attack, subject="R", path=None
            )
            == []
        )

    def test_analytics_are_validated(self, attack: AttackCatalog) -> None:
        findings = validate_identifiers(
            ["AN9999"], "analytics", catalog=attack, subject="R", path=None
        )
        assert codes(findings) == {"SDEL-ATT-005"}

    def test_data_components_are_validated(self, attack: AttackCatalog) -> None:
        assert (
            validate_identifiers(
                ["DC0001"], "data_components", catalog=attack, subject="R", path=None
            )
            == []
        )

    def test_the_path_is_carried_through(self, attack: AttackCatalog) -> None:
        findings = validate_identifiers(
            ["T9998"], "techniques", catalog=attack, subject="R", path="metadata/x.json"
        )
        assert findings[0].path == "metadata/x.json"

    def test_every_finding_is_categorised_as_attack(self, attack: AttackCatalog) -> None:
        findings = validate_identifiers(
            ["T9998"], "techniques", catalog=attack, subject="R", path=None
        )
        assert all(str(finding.category) == "attack" for finding in findings)


class TestMappingValidation:
    def test_a_valid_mapping_passes(self, attack: AttackCatalog) -> None:
        mapping = AttackMapping(techniques=("T1204.002",), tactics=("TA0002",))
        assert validate_mapping(mapping, catalog=attack, subject="R") == []

    def test_an_unexplained_empty_mapping_is_reported(self, attack: AttackCatalog) -> None:
        findings = validate_mapping(AttackMapping(), catalog=attack, subject="R")
        assert codes(findings) == {"SDEL-ATT-010"}

    def test_an_unexplained_gap_is_high_severity(self, attack: AttackCatalog) -> None:
        findings = validate_mapping(AttackMapping(), catalog=attack, subject="R")
        assert findings[0].severity is Severity.HIGH

    def test_a_thin_reason_is_reported(self, attack: AttackCatalog) -> None:
        findings = validate_mapping(AttackMapping(reason="none"), catalog=attack, subject="R")
        assert codes(findings) == {"SDEL-ATT-011"}

    def test_a_substantial_reason_is_accepted(self, attack: AttackCatalog) -> None:
        reason = "x" * MIN_REASON_LENGTH
        assert validate_mapping(AttackMapping(reason=reason), catalog=attack, subject="R") == []

    def test_a_reason_of_whitespace_counts_as_absent(self, attack: AttackCatalog) -> None:
        findings = validate_mapping(AttackMapping(reason="   "), catalog=attack, subject="R")
        assert codes(findings) == {"SDEL-ATT-010"}

    def test_every_object_type_is_checked(self, attack: AttackCatalog) -> None:
        mapping = AttackMapping(
            techniques=("T9998",),
            tactics=("TA9998",),
            detection_strategies=("DET9998",),
            analytics=("AN9998",),
            data_components=("DC9998",),
        )
        findings = validate_mapping(mapping, catalog=attack, subject="R")
        assert len(findings) == 5

    def test_an_inconsistent_tactic_is_reported(self, attack: AttackCatalog) -> None:
        mapping = AttackMapping(techniques=("T1204.002",), tactics=("TA0006",))
        findings = validate_mapping(mapping, catalog=attack, subject="R")
        assert "SDEL-ATT-012" in codes(findings)

    def test_a_consistent_tactic_passes(self, attack: AttackCatalog) -> None:
        mapping = AttackMapping(techniques=("T1003.001",), tactics=("TA0006",))
        assert "SDEL-ATT-012" not in codes(validate_mapping(mapping, catalog=attack, subject="R"))

    def test_consistency_is_skipped_without_a_catalog(self) -> None:
        mapping = AttackMapping(techniques=("T1204.002",), tactics=("TA0006",))
        findings = validate_mapping(mapping, catalog=AttackCatalog(), subject="R")
        assert "SDEL-ATT-012" not in codes(findings)

    def test_consistency_falls_back_to_the_parent_technique(self, attack: AttackCatalog) -> None:
        mapping = AttackMapping(techniques=("T1204.999",), tactics=("TA0002",))
        findings = validate_mapping(mapping, catalog=attack, subject="R")
        assert "SDEL-ATT-012" not in codes(findings)


class TestRuleTagValidation:
    def test_valid_tags_pass(self, attack: AttackCatalog) -> None:
        rule = make_rule(tags=("attack.execution", "attack.t1204.002"))
        assert validate_rule_tags(rule, catalog=attack) == []

    def test_an_invented_technique_tag_is_reported(self, attack: AttackCatalog) -> None:
        rule = make_rule(tags=("attack.t9998",))
        assert codes(validate_rule_tags(rule, catalog=attack)) == {"SDEL-ATT-005"}

    def test_an_invented_tactic_tag_is_reported(self, attack: AttackCatalog) -> None:
        rule = make_rule(tags=("attack.teleportation",))
        assert codes(validate_rule_tags(rule, catalog=attack)) == {"SDEL-ATT-005"}

    def test_non_attack_tags_are_ignored(self, attack: AttackCatalog) -> None:
        rule = make_rule(tags=("tlp.clear", "cve.2024-0001"))
        assert validate_rule_tags(rule, catalog=attack) == []

    def test_a_rule_without_tags_passes(self, attack: AttackCatalog) -> None:
        assert validate_rule_tags(make_rule(tags=()), catalog=attack) == []

    def test_findings_name_the_rule(self, attack: AttackCatalog) -> None:
        rule = make_rule("SDEL-WIN-009", tags=("attack.t9998",))
        assert validate_rule_tags(rule, catalog=attack)[0].subject == "SDEL-WIN-009"

    def test_findings_carry_the_rule_path(self, attack: AttackCatalog) -> None:
        rule = make_rule(tags=("attack.t9998",))
        assert validate_rule_tags(rule, catalog=attack)[0].path == rule.relative_path


class TestTagSidecarAgreement:
    def test_agreement_produces_no_findings(self) -> None:
        rule = make_rule(tags=("attack.t1204.002",))
        sidecar = make_sidecar(attack_mapping=AttackMapping(techniques=("T1204.002",)))
        assert validate_tag_sidecar_agreement(rule, sidecar) == []

    def test_a_tag_missing_from_the_sidecar_is_reported(self) -> None:
        rule = make_rule(tags=("attack.t1204.002", "attack.t1003.001"))
        sidecar = make_sidecar(attack_mapping=AttackMapping(techniques=("T1204.002",)))
        assert codes(validate_tag_sidecar_agreement(rule, sidecar)) == {"SDEL-ATT-020"}

    def test_a_sidecar_technique_missing_from_the_tags_is_reported(self) -> None:
        rule = make_rule(tags=("attack.t1204.002",))
        sidecar = make_sidecar(attack_mapping=AttackMapping(techniques=("T1204.002", "T1003.001")))
        assert codes(validate_tag_sidecar_agreement(rule, sidecar)) == {"SDEL-ATT-021"}

    def test_both_directions_can_be_reported_at_once(self) -> None:
        rule = make_rule(tags=("attack.t1059",))
        sidecar = make_sidecar(attack_mapping=AttackMapping(techniques=("T1204.002",)))
        assert codes(validate_tag_sidecar_agreement(rule, sidecar)) == {
            "SDEL-ATT-020",
            "SDEL-ATT-021",
        }

    def test_comparison_is_case_insensitive(self) -> None:
        rule = make_rule(tags=("attack.T1204.002",))
        sidecar = make_sidecar(attack_mapping=AttackMapping(techniques=("t1204.002",)))
        assert validate_tag_sidecar_agreement(rule, sidecar) == []

    def test_the_missing_technique_is_named(self) -> None:
        rule = make_rule(tags=("attack.t1059",))
        sidecar = make_sidecar(attack_mapping=AttackMapping(techniques=("T1059",)))
        assert validate_tag_sidecar_agreement(rule, sidecar) == []

    def test_an_empty_sidecar_mapping_reports_the_tags(self) -> None:
        rule = make_rule(tags=("attack.t1204.002",))
        sidecar = make_sidecar(attack_mapping=AttackMapping())
        assert codes(validate_tag_sidecar_agreement(rule, sidecar)) == {"SDEL-ATT-020"}

    def test_the_remediation_suggests_adding_the_tag(self) -> None:
        rule = make_rule(tags=())
        sidecar = make_sidecar(attack_mapping=AttackMapping(techniques=("T1204.002",)))
        assert "attack.<technique>" in validate_tag_sidecar_agreement(rule, sidecar)[0].remediation


class TestCatalogWideValidation:
    def test_a_clean_catalog_produces_no_findings(self, attack: AttackCatalog) -> None:
        rule = make_rule("SDEL-TST-001", tags=("attack.t1204.002", "attack.execution"))
        sidecar = make_sidecar(
            "SDEL-TST-001",
            attack_mapping=AttackMapping(techniques=("T1204.002",), tactics=("TA0002",)),
        )
        findings = validate_catalog(RuleCatalog([rule]), MetadataSet(sidecars=(sidecar,)), attack)
        assert findings == []

    def test_catalog_load_errors_are_reported(self) -> None:
        broken = AttackCatalog(load_errors=(("data/attack/x.json", "boom"),))
        findings = validate_catalog(RuleCatalog([]), MetadataSet(), broken)
        assert codes(findings) == {"SDEL-ATT-000"}

    def test_a_rule_without_a_sidecar_is_still_tag_checked(self, attack: AttackCatalog) -> None:
        rule = make_rule("SDEL-TST-001", tags=("attack.t9998",))
        findings = validate_catalog(RuleCatalog([rule]), MetadataSet(), attack)
        assert codes(findings) == {"SDEL-ATT-005"}

    def test_sidecar_mappings_are_validated(self, attack: AttackCatalog) -> None:
        rule = make_rule("SDEL-TST-001", tags=())
        sidecar = make_sidecar("SDEL-TST-001", attack_mapping=AttackMapping(techniques=("T9998",)))
        findings = validate_catalog(RuleCatalog([rule]), MetadataSet(sidecars=(sidecar,)), attack)
        assert "SDEL-ATT-005" in codes(findings)

    def test_drift_between_tags_and_sidecars_is_reported(self, attack: AttackCatalog) -> None:
        rule = make_rule("SDEL-TST-001", tags=("attack.t1204.002",))
        sidecar = make_sidecar(
            "SDEL-TST-001",
            attack_mapping=AttackMapping(techniques=("T1003.001",), tactics=("TA0006",)),
        )
        findings = validate_catalog(RuleCatalog([rule]), MetadataSet(sidecars=(sidecar,)), attack)
        assert {"SDEL-ATT-020", "SDEL-ATT-021"} <= codes(findings)

    def test_an_empty_catalog_produces_no_findings(self, attack: AttackCatalog) -> None:
        assert validate_catalog(RuleCatalog([]), MetadataSet(), attack) == []


class TestCoverageCounters:
    def test_techniques_are_counted(self) -> None:
        metadata = MetadataSet(
            sidecars=(
                make_sidecar("a", attack_mapping=AttackMapping(techniques=("T1204.002",))),
                make_sidecar("b", attack_mapping=AttackMapping(techniques=("T1204.002",))),
            )
        )
        assert mapped_techniques(metadata) == {"T1204.002": 2}

    def test_technique_counts_are_uppercased(self) -> None:
        metadata = MetadataSet(
            sidecars=(make_sidecar(attack_mapping=AttackMapping(techniques=("t1204",))),)
        )
        assert mapped_techniques(metadata) == {"T1204": 1}

    def test_technique_counts_are_sorted(self) -> None:
        metadata = MetadataSet(
            sidecars=(
                make_sidecar("a", attack_mapping=AttackMapping(techniques=("T9000", "T1000"))),
            )
        )
        assert list(mapped_techniques(metadata)) == ["T1000", "T9000"]

    def test_tactics_are_counted(self) -> None:
        metadata = MetadataSet(
            sidecars=(make_sidecar(attack_mapping=AttackMapping(tactics=("TA0002",))),)
        )
        assert mapped_tactics(metadata) == {"ta0002": 1}

    def test_tactic_counts_are_lowercased(self) -> None:
        metadata = MetadataSet(
            sidecars=(make_sidecar(attack_mapping=AttackMapping(tactics=("Execution",))),)
        )
        assert mapped_tactics(metadata) == {"execution": 1}

    def test_an_empty_set_counts_nothing(self) -> None:
        assert mapped_techniques(MetadataSet()) == {}
        assert mapped_tactics(MetadataSet()) == {}


class TestRealMappings:
    def test_the_real_project_maps_cleanly(
        self, real_catalog: RuleCatalog, real_metadata: MetadataSet, real_config: LabConfig
    ) -> None:
        attack = load_attack_catalog(real_config)
        findings = validate_catalog(real_catalog, real_metadata, attack)
        assert [f"{finding.code}:{finding.subject}" for finding in findings] == []

    def test_the_real_project_maps_to_techniques(self, real_metadata: MetadataSet) -> None:
        assert mapped_techniques(real_metadata)

    def test_the_real_project_maps_to_tactics(self, real_metadata: MetadataSet) -> None:
        assert mapped_tactics(real_metadata)

    def test_every_real_technique_exists_in_the_vendored_catalog(
        self, real_metadata: MetadataSet, real_config: LabConfig
    ) -> None:
        attack = load_attack_catalog(real_config)
        missing = [
            technique
            for technique in mapped_techniques(real_metadata)
            if attack.get_technique(technique) is None
        ]
        assert missing == []
