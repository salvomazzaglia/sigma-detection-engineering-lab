"""Project authoring conventions, which are stricter than Sigma on purpose."""

from __future__ import annotations

from typing import Any

import pytest

from conftest import make_rule
from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.convention_validation import (
    ALLOWED_UUID_VERSIONS,
    BANNED_FALSEPOSITIVES,
    MIN_FALSEPOSITIVE_LENGTH,
    TAG_PATTERN,
    allowed_statuses,
    banned_falsepositives,
    validate_author,
    validate_catalog,
    validate_falsepositives,
    validate_filename,
    validate_license,
    validate_references,
    validate_rule,
    validate_status,
    validate_tags,
    validate_title_uniqueness,
    validate_uuid,
)
from sigma_detection_engineering_lab.models import FindingCategory
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.severities import Severity
from sigma_detection_engineering_lab.statuses import SigmaStatus

GOOD_FALSEPOSITIVE = "Packaging pipelines that stage build artefacts in the same directory."


def codes(findings: list[Any]) -> list[str]:
    return [finding.code for finding in findings]


class TestAuthor:
    def test_the_declared_author_passes(self, tiny_config: LabConfig) -> None:
        rule = make_rule(author=tiny_config.required_authors[0])
        assert validate_author(rule, tiny_config) == []

    def test_a_missing_author_is_reported(self, tiny_config: LabConfig) -> None:
        assert codes(validate_author(make_rule(author=""), tiny_config)) == ["SDEL-CNV-001"]

    def test_a_missing_author_suggests_the_project_author(self, tiny_config: LabConfig) -> None:
        finding = validate_author(make_rule(author=""), tiny_config)[0]
        assert tiny_config.required_authors[0] in finding.remediation

    def test_a_different_author_is_reported(self, tiny_config: LabConfig) -> None:
        rule = make_rule(author="Somebody Else")
        assert codes(validate_author(rule, tiny_config)) == ["SDEL-CNV-002"]

    def test_a_co_author_list_containing_the_project_author_passes(
        self, tiny_config: LabConfig
    ) -> None:
        rule = make_rule(author=f"{tiny_config.required_authors[0]}, Somebody Else")
        assert validate_author(rule, tiny_config) == []

    def test_surrounding_space_in_the_list_is_tolerated(self, tiny_config: LabConfig) -> None:
        rule = make_rule(author=f"  {tiny_config.required_authors[0]}  ")
        assert validate_author(rule, tiny_config) == []

    def test_the_finding_explains_the_originality_claim(self, tiny_config: LabConfig) -> None:
        finding = validate_author(make_rule(author="Somebody Else"), tiny_config)[0]
        assert "original rules only" in finding.remediation

    def test_author_findings_name_the_gate(self, tiny_config: LabConfig) -> None:
        assert validate_author(make_rule(author=""), tiny_config)[0].gate == "required_metadata"


class TestLicense:
    def test_the_project_licence_passes(self, tiny_config: LabConfig) -> None:
        assert validate_license(make_rule(license_value=tiny_config.license), tiny_config) == []

    def test_a_missing_licence_is_reported(self, tiny_config: LabConfig) -> None:
        assert codes(validate_license(make_rule(license_value=None), tiny_config)) == [
            "SDEL-CNV-003"
        ]

    def test_a_different_licence_is_reported(self, tiny_config: LabConfig) -> None:
        assert codes(validate_license(make_rule(license_value="Apache-2.0"), tiny_config)) == [
            "SDEL-CNV-004"
        ]

    def test_licence_matching_ignores_case(self, tiny_config: LabConfig) -> None:
        rule = make_rule(license_value=tiny_config.license.lower())
        assert validate_license(rule, tiny_config) == []

    def test_a_licence_mismatch_is_high_severity(self, tiny_config: LabConfig) -> None:
        finding = validate_license(make_rule(license_value="GPL-3.0"), tiny_config)[0]
        assert finding.severity is Severity.HIGH


class TestUuid:
    def test_a_version_four_uuid_passes(self) -> None:
        assert validate_uuid(make_rule(rule_id="11111111-1111-4111-8111-111111111111")) == []

    def test_a_missing_uuid_is_critical(self) -> None:
        findings = validate_uuid(make_rule(rule_id=""))
        assert codes(findings) == ["SDEL-CNV-010"]
        assert findings[0].severity is Severity.CRITICAL

    def test_a_malformed_uuid_is_critical(self) -> None:
        assert codes(validate_uuid(make_rule(rule_id="not-a-uuid"))) == ["SDEL-CNV-011"]

    def test_an_uppercase_uuid_is_accepted_as_canonical(self) -> None:
        assert (
            validate_uuid(make_rule(rule_id="11111111-1111-4111-8111-111111111111".upper())) == []
        )

    def test_an_unhyphenated_uuid_is_only_advisory(self) -> None:
        findings = validate_uuid(make_rule(rule_id="11111111111141118111111111111111"))
        assert codes(findings) == ["SDEL-CNV-012"]
        assert findings[0].severity is Severity.LOW

    def test_the_canonical_form_is_suggested(self) -> None:
        findings = validate_uuid(make_rule(rule_id="11111111111141118111111111111111"))
        assert "11111111-1111-4111-8111-111111111111" in findings[0].remediation

    def test_a_version_one_uuid_is_reported(self) -> None:
        assert codes(validate_uuid(make_rule(rule_id="11111111-1111-1111-8111-111111111111"))) == [
            "SDEL-CNV-013"
        ]

    def test_a_version_five_uuid_passes(self) -> None:
        assert validate_uuid(make_rule(rule_id="11111111-1111-5111-8111-111111111111")) == []

    def test_the_allowed_versions_are_four_and_five(self) -> None:
        assert frozenset({4, 5}) == ALLOWED_UUID_VERSIONS

    def test_uuid_findings_name_the_uniqueness_gate(self) -> None:
        assert validate_uuid(make_rule(rule_id=""))[0].gate == "unique_uuid"


class TestFilename:
    def test_a_conventional_filename_passes(self) -> None:
        rule = make_rule(relative_path="rules/windows/process_creation/suspicious_thing.yml")
        assert validate_filename(rule) == []

    @pytest.mark.parametrize(
        "name",
        [
            "rules/windows/Suspicious_Thing.yml",
            "rules/windows/suspicious thing.yml",
            "rules/windows/suspicious-thing.yaml",
            "rules/windows/suspicious.thing.yml",
        ],
    )
    def test_an_unconventional_filename_is_reported(self, name: str) -> None:
        assert codes(validate_filename(make_rule(relative_path=name))) == ["SDEL-CNV-020"]

    def test_the_finding_states_the_convention(self) -> None:
        rule = make_rule(relative_path="rules/windows/BAD.yml")
        assert "lowercase words" in validate_filename(rule)[0].remediation

    def test_filename_findings_name_the_gate(self) -> None:
        rule = make_rule(relative_path="rules/windows/BAD.yml")
        assert validate_filename(rule)[0].gate == "valid_filename"


class TestStatus:
    def test_an_allowed_status_passes(self, tiny_config: LabConfig) -> None:
        rule = make_rule(status=SigmaStatus.EXPERIMENTAL)
        assert validate_status(rule, tiny_config) == []

    def test_the_test_status_passes(self, tiny_config: LabConfig) -> None:
        assert validate_status(make_rule(status=SigmaStatus.TEST), tiny_config) == []

    def test_stable_is_blocked(self, tiny_config: LabConfig) -> None:
        findings = validate_status(make_rule(status=SigmaStatus.STABLE), tiny_config)
        assert codes(findings) == ["SDEL-CNV-030"]

    def test_the_block_on_stable_is_critical(self, tiny_config: LabConfig) -> None:
        findings = validate_status(make_rule(status=SigmaStatus.STABLE), tiny_config)
        assert findings[0].severity is Severity.CRITICAL

    def test_the_block_explains_why(self, tiny_config: LabConfig) -> None:
        findings = validate_status(make_rule(status=SigmaStatus.STABLE), tiny_config)
        assert "synthetic testing cannot substantiate" in findings[0].message

    def test_the_block_suggests_the_alternatives(self, tiny_config: LabConfig) -> None:
        findings = validate_status(make_rule(status=SigmaStatus.STABLE), tiny_config)
        assert "experimental" in findings[0].remediation

    def test_a_retired_status_is_high_rather_than_critical(self, tiny_config: LabConfig) -> None:
        findings = validate_status(make_rule(status=SigmaStatus.DEPRECATED), tiny_config)
        assert findings[0].severity is Severity.HIGH

    def test_a_retired_status_is_still_reported(self, tiny_config: LabConfig) -> None:
        findings = validate_status(make_rule(status=SigmaStatus.DEPRECATED), tiny_config)
        assert codes(findings) == ["SDEL-CNV-031"]

    def test_the_allowed_statuses_are_listed(self, tiny_config: LabConfig) -> None:
        findings = validate_status(make_rule(status=SigmaStatus.DEPRECATED), tiny_config)
        assert "experimental" in findings[0].message

    def test_the_allowed_status_helper_is_sorted(self, tiny_config: LabConfig) -> None:
        values = [status.value for status in allowed_statuses(tiny_config)]
        assert values == sorted(values)


class TestReferences:
    def test_a_single_url_passes(self) -> None:
        assert validate_references(make_rule(references=("https://example.invalid/a",))) == []

    def test_no_references_is_reported(self) -> None:
        assert codes(validate_references(make_rule(references=()))) == ["SDEL-CNV-040"]

    def test_no_references_asks_for_the_reasoning(self) -> None:
        assert "motivated" in validate_references(make_rule(references=()))[0].remediation

    def test_an_empty_reference_is_reported(self) -> None:
        rule = make_rule(references=("https://example.invalid/a", "  "))
        assert codes(validate_references(rule)) == ["SDEL-CNV-041"]

    def test_a_non_url_reference_is_only_advisory(self) -> None:
        rule = make_rule(references=("see the internal wiki",))
        findings = validate_references(rule)
        assert codes(findings) == ["SDEL-CNV-042"]
        assert findings[0].severity is Severity.LOW

    def test_an_http_url_is_accepted(self) -> None:
        assert validate_references(make_rule(references=("http://example.invalid/a",))) == []

    def test_the_index_is_reported(self) -> None:
        rule = make_rule(references=("https://example.invalid/a", "wiki"))
        assert "references[1]" in validate_references(rule)[0].message

    def test_reference_findings_name_the_gate(self) -> None:
        assert validate_references(make_rule(references=()))[0].gate == "non_empty_references"


class TestFalsePositives:
    def test_a_specific_entry_passes(self) -> None:
        assert validate_falsepositives(make_rule(falsepositives=(GOOD_FALSEPOSITIVE,))) == []

    def test_no_entries_is_reported(self) -> None:
        assert codes(validate_falsepositives(make_rule(falsepositives=()))) == ["SDEL-CNV-050"]

    def test_no_entries_asks_for_benign_activity(self) -> None:
        finding = validate_falsepositives(make_rule(falsepositives=()))[0]
        assert "benign activity" in finding.remediation

    def test_an_empty_entry_is_reported(self) -> None:
        rule = make_rule(falsepositives=(GOOD_FALSEPOSITIVE, "   "))
        assert codes(validate_falsepositives(rule)) == ["SDEL-CNV-051"]

    @pytest.mark.parametrize("placeholder", sorted(BANNED_FALSEPOSITIVES))
    def test_every_placeholder_is_refused(self, placeholder: str) -> None:
        rule = make_rule(falsepositives=(placeholder,))
        assert codes(validate_falsepositives(rule)) == ["SDEL-CNV-052"]

    def test_a_placeholder_is_refused_regardless_of_case(self) -> None:
        assert codes(validate_falsepositives(make_rule(falsepositives=("Unknown",)))) == [
            "SDEL-CNV-052"
        ]

    def test_a_trailing_full_stop_does_not_evade_the_check(self) -> None:
        assert codes(validate_falsepositives(make_rule(falsepositives=("Unknown.",)))) == [
            "SDEL-CNV-052"
        ]

    def test_a_placeholder_asks_for_the_concrete_scenario(self) -> None:
        finding = validate_falsepositives(make_rule(falsepositives=("unknown",)))[0]
        assert "concrete benign scenario" in finding.remediation

    def test_a_short_entry_is_reported(self) -> None:
        rule = make_rule(falsepositives=("x" * (MIN_FALSEPOSITIVE_LENGTH - 1),))
        assert codes(validate_falsepositives(rule)) == ["SDEL-CNV-053"]

    def test_an_entry_at_the_minimum_length_passes(self) -> None:
        rule = make_rule(falsepositives=("x" * MIN_FALSEPOSITIVE_LENGTH,))
        assert validate_falsepositives(rule) == []

    def test_the_banned_set_can_be_extended(self) -> None:
        assert "site-specific placeholder" in banned_falsepositives(("Site-Specific Placeholder",))

    def test_extending_keeps_the_defaults(self) -> None:
        assert "unknown" in banned_falsepositives(("extra",))

    def test_extending_ignores_blank_entries(self) -> None:
        assert banned_falsepositives(("  ",)) == BANNED_FALSEPOSITIVES

    def test_falsepositive_findings_name_the_specificity_gate(self) -> None:
        finding = validate_falsepositives(make_rule(falsepositives=("unknown",)))[0]
        assert finding.gate == "specific_falsepositives"


class TestTags:
    def test_conventional_tags_pass(self) -> None:
        assert validate_tags(make_rule(tags=("attack.t1059.001", "attack.execution"))) == []

    @pytest.mark.parametrize("tag", ["Attack.T1059", "attack t1059", "attack..t1059", "_attack"])
    def test_a_malformed_tag_is_reported(self, tag: str) -> None:
        assert codes(validate_tags(make_rule(tags=(tag,)))) == ["SDEL-CNV-060"]

    def test_a_duplicated_tag_is_reported(self) -> None:
        findings = validate_tags(make_rule(tags=("attack.execution", "attack.execution")))
        assert codes(findings) == ["SDEL-CNV-061"]

    def test_a_duplicate_is_only_advisory(self) -> None:
        findings = validate_tags(make_rule(tags=("attack.execution", "attack.execution")))
        assert findings[0].severity is Severity.LOW

    def test_duplicate_detection_ignores_case(self) -> None:
        findings = validate_tags(make_rule(tags=("attack.execution", "ATTACK.EXECUTION")))
        assert "SDEL-CNV-061" in codes(findings)

    def test_a_hyphenated_tag_is_accepted(self) -> None:
        assert validate_tags(make_rule(tags=("attack.defense-evasion",))) == []

    def test_an_underscore_tag_is_accepted(self) -> None:
        assert validate_tags(make_rule(tags=("cve_2026_0001",))) == []

    def test_no_tags_reports_nothing(self) -> None:
        assert validate_tags(make_rule(tags=())) == []

    @pytest.mark.parametrize("tag", ["attack.t1059", "a", "a1.b2-c3_d4"])
    def test_accepted_tag_shapes(self, tag: str) -> None:
        assert TAG_PATTERN.match(tag)

    def test_tag_findings_name_the_attack_gate(self) -> None:
        assert validate_tags(make_rule(tags=("BAD",)))[0].gate == "valid_attack_tags"


class TestTitleUniqueness:
    def test_distinct_titles_pass(self) -> None:
        catalog = RuleCatalog(
            [
                make_rule(catalog_id="a", title="One", rule_id="1"),
                make_rule(catalog_id="b", title="Two", rule_id="2"),
            ]
        )
        assert validate_title_uniqueness(catalog) == []

    def test_a_duplicate_title_is_reported(self) -> None:
        catalog = RuleCatalog(
            [
                make_rule(catalog_id="a", title="Same", rule_id="1"),
                make_rule(catalog_id="b", title="Same", rule_id="2"),
            ]
        )
        assert codes(validate_title_uniqueness(catalog)) == ["SDEL-CNV-070"]

    def test_duplicate_detection_ignores_case(self) -> None:
        catalog = RuleCatalog(
            [
                make_rule(catalog_id="a", title="Same", rule_id="1"),
                make_rule(catalog_id="b", title="SAME", rule_id="2"),
            ]
        )
        assert len(validate_title_uniqueness(catalog)) == 1

    def test_the_first_file_is_named(self) -> None:
        catalog = RuleCatalog(
            [
                make_rule(catalog_id="a", title="Same", rule_id="1", relative_path="one.yml"),
                make_rule(catalog_id="b", title="Same", rule_id="2", relative_path="two.yml"),
            ]
        )
        assert "one.yml" in validate_title_uniqueness(catalog)[0].message

    def test_three_duplicates_produce_two_findings(self) -> None:
        catalog = RuleCatalog(
            [make_rule(catalog_id=name, title="Same", rule_id=name) for name in ("a", "b", "c")]
        )
        assert len(validate_title_uniqueness(catalog)) == 2


class TestCombined:
    def test_a_conventional_rule_reports_nothing(self, tiny_config: LabConfig) -> None:
        rule = make_rule(
            author=tiny_config.required_authors[0],
            license_value=tiny_config.license,
            falsepositives=(GOOD_FALSEPOSITIVE,),
        )
        assert validate_rule(rule, config=tiny_config) == []

    def test_findings_from_several_checks_accumulate(self, tiny_config: LabConfig) -> None:
        rule = make_rule(author="", license_value=None, rule_id="", references=())
        found = set(codes(validate_rule(rule, config=tiny_config)))
        assert {"SDEL-CNV-001", "SDEL-CNV-003", "SDEL-CNV-010", "SDEL-CNV-040"} <= found

    def test_every_finding_is_a_convention_finding(self, tiny_config: LabConfig) -> None:
        rule = make_rule(author="", license_value=None)
        findings = validate_rule(rule, config=tiny_config)
        assert all(f.category is FindingCategory.CONVENTION for f in findings)

    def test_catalog_validation_includes_title_uniqueness(self, tiny_config: LabConfig) -> None:
        catalog = RuleCatalog(
            [
                make_rule(
                    catalog_id=name,
                    title="Same",
                    rule_id=f"{index}1111111-1111-4111-8111-111111111111",
                    author=tiny_config.required_authors[0],
                    license_value=tiny_config.license,
                    falsepositives=(GOOD_FALSEPOSITIVE,),
                )
                for index, name in enumerate(("a", "b"))
            ]
        )
        assert codes(validate_catalog(catalog, config=tiny_config)) == ["SDEL-CNV-070"]

    def test_an_empty_catalog_reports_nothing(self, tiny_config: LabConfig) -> None:
        assert validate_catalog(RuleCatalog([]), config=tiny_config) == []


class TestRealCatalog:
    def test_the_real_catalog_follows_every_convention(
        self, real_catalog: RuleCatalog, real_config: LabConfig
    ) -> None:
        findings = validate_catalog(real_catalog, config=real_config)
        assert [f"{f.code} {f.subject}: {f.message}" for f in findings] == []

    def test_no_real_rule_claims_stable(self, real_catalog: RuleCatalog) -> None:
        assert [r.catalog_id for r in real_catalog if r.status is SigmaStatus.STABLE] == []

    def test_every_real_rule_has_references(self, real_catalog: RuleCatalog) -> None:
        assert [r.catalog_id for r in real_catalog if not r.references] == []

    def test_every_real_rule_has_specific_falsepositives(self, real_catalog: RuleCatalog) -> None:
        assert [r.catalog_id for r in real_catalog if validate_falsepositives(r)] == []

    def test_every_real_title_is_unique(self, real_catalog: RuleCatalog) -> None:
        assert validate_title_uniqueness(real_catalog) == []
