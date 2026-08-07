"""Rule loading: filenames, document splitting, field coercion, and failures."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from tests.conftest import SAMPLE_RULE_TEXT, make_rule

from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.errors import RuleLoadError
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog, RuleFilter
from sigma_detection_engineering_lab.rule_loader import (
    KNOWN_RULE_KEYS,
    RULE_FILENAME_PATTERN,
    build_rule,
    correlation_base_documents,
    derive_catalog_id,
    discover_rule_files,
    is_valid_rule_filename,
    load_rule_file,
    load_rules,
    parse_with_pysigma,
    pysigma_status,
)
from sigma_detection_engineering_lab.severities import Severity
from sigma_detection_engineering_lab.statuses import SigmaStatus


def minimal_document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "title": "Synthetic Rule",
        "id": "11111111-2222-4333-8444-555555555555",
        "status": "experimental",
        "description": "A synthetic rule.",
        "author": "Salvatore Mazzaglia",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"selection": {"Image": "cmd.exe"}, "condition": "selection"},
        "level": "medium",
    }
    document.update(overrides)
    return document


def build(document: Any, *, name: str = "synthetic_rule.yml") -> Any:
    documents = document if isinstance(document, list) else [document]
    return build_rule(
        documents,
        path=Path(f"rules/windows/{name}"),
        relative_path=f"rules/windows/{name}",
    )


class TestFilenameConvention:
    @pytest.mark.parametrize(
        "name",
        [
            "simple.yml",
            "two_words.yml",
            "three_word_name.yml",
            "hyphen-separated.yml",
            "mixed_style-name.yml",
            "digits123.yml",
            "t1003_lsass_access.yml",
        ],
    )
    def test_conventional_names_are_accepted(self, name: str) -> None:
        assert is_valid_rule_filename(Path(name)) is True

    @pytest.mark.parametrize(
        "name",
        [
            "Uppercase.yml",
            "trailing_.yml",
            "_leading.yml",
            "double__underscore.yml",
            "spaces in name.yml",
            "extension.yaml",
            "no_extension",
            "dotted.name.yml",
        ],
    )
    def test_unconventional_names_are_rejected(self, name: str) -> None:
        assert is_valid_rule_filename(Path(name)) is False

    def test_the_pattern_is_anchored_at_both_ends(self) -> None:
        assert RULE_FILENAME_PATTERN.match("prefix rule.yml") is None
        assert RULE_FILENAME_PATTERN.match("rule.yml suffix") is None

    def test_catalog_id_is_the_filename_stem(self) -> None:
        assert derive_catalog_id(Path("rules/windows/a_rule.yml")) == "a_rule"

    def test_catalog_id_ignores_the_directory(self) -> None:
        first = derive_catalog_id(Path("rules/windows/x.yml"))
        second = derive_catalog_id(Path("rules/linux/x.yml"))
        assert first == second == "x"


class TestDocumentStructure:
    def test_a_minimal_document_builds(self) -> None:
        rule = build(minimal_document())
        assert rule.title == "Synthetic Rule"

    def test_an_empty_document_list_is_refused(self) -> None:
        with pytest.raises(RuleLoadError, match="no YAML documents"):
            build_rule([], path=Path("rules/x.yml"), relative_path="rules/x.yml")

    def test_two_plain_documents_are_refused(self) -> None:
        with pytest.raises(RuleLoadError, match="multi-document files"):
            build([minimal_document(), minimal_document()])

    def test_two_correlation_documents_are_refused(self) -> None:
        correlation = minimal_document(correlation={"type": "event_count"})
        with pytest.raises(RuleLoadError, match="correlation documents"):
            build([correlation, dict(correlation)])

    def test_a_base_plus_correlation_pair_is_accepted(self) -> None:
        base = minimal_document(name="base_rule")
        correlation = {
            "title": "Correlated",
            "id": "22222222-3333-4444-8555-666666666666",
            "status": "experimental",
            "correlation": {"type": "event_count", "rules": ["base_rule"]},
        }
        rule = build([base, correlation])
        assert rule.is_correlation is True
        assert rule.title == "Correlated"

    def test_the_correlation_document_wins_regardless_of_order(self) -> None:
        base = minimal_document(name="base_rule")
        correlation = {
            "title": "Correlated",
            "correlation": {"type": "event_count", "rules": ["base_rule"]},
        }
        first = build([correlation, base])
        second = build([base, correlation])
        assert first.title == second.title == "Correlated"

    def test_all_documents_are_retained(self) -> None:
        base = minimal_document(name="base_rule")
        correlation = {"title": "C", "correlation": {"type": "event_count"}}
        assert len(build([base, correlation]).documents) == 2

    def test_unknown_top_level_keys_are_refused(self) -> None:
        with pytest.raises(RuleLoadError, match="unknown top-level key"):
            build(minimal_document(nonsense=1))

    def test_the_error_names_the_offending_key(self) -> None:
        with pytest.raises(RuleLoadError, match="nonsense"):
            build(minimal_document(nonsense=1))

    def test_every_known_key_is_accepted_together(self) -> None:
        document = minimal_document(
            name="a_name",
            related=[{"id": "33333333-4444-4555-8666-777777777777", "type": "similar"}],
            references=["https://example.invalid/a"],
            date="2026-01-01",
            modified="2026-02-01",
            tags=["attack.execution"],
            fields=["Image"],
            falsepositives=["Unknown"],
            license="MIT",
            scope="synthetic",
        )
        assert set(document) <= KNOWN_RULE_KEYS
        assert build(document).name == "a_name"

    def test_title_is_required(self) -> None:
        document = minimal_document()
        del document["title"]
        with pytest.raises(RuleLoadError, match="'title' is required"):
            build(document)

    def test_a_blank_title_is_refused(self) -> None:
        with pytest.raises(RuleLoadError, match="non-empty string"):
            build(minimal_document(title="   "))

    def test_a_non_string_title_is_refused(self) -> None:
        with pytest.raises(RuleLoadError, match="non-empty string"):
            build(minimal_document(title=7))

    def test_detection_is_required_for_a_plain_rule(self) -> None:
        document = minimal_document()
        del document["detection"]
        with pytest.raises(RuleLoadError, match="'detection' is required"):
            build(document)

    def test_detection_must_be_a_mapping(self) -> None:
        with pytest.raises(RuleLoadError, match="'detection' must be a mapping"):
            build(minimal_document(detection=["selection"]))

    def test_correlation_must_be_a_mapping(self) -> None:
        with pytest.raises(RuleLoadError, match="'correlation' must be a mapping"):
            build(minimal_document(correlation=["event_count"]))

    def test_a_correlation_rule_needs_no_detection(self) -> None:
        document = {"title": "C", "correlation": {"type": "event_count"}}
        assert build(document).detection == {}

    def test_logsource_must_be_a_mapping(self) -> None:
        with pytest.raises(RuleLoadError, match="'logsource' must be a mapping"):
            build(minimal_document(logsource="windows"))

    def test_related_entries_must_be_mappings(self) -> None:
        with pytest.raises(RuleLoadError, match="'related' entry"):
            build(minimal_document(related=["not-a-mapping"]))

    def test_related_must_be_a_list(self) -> None:
        with pytest.raises(RuleLoadError, match="'related' must be a list"):
            build(minimal_document(related="similar"))

    def test_related_entries_are_preserved(self) -> None:
        entry = {"id": "33333333-4444-4555-8666-777777777777", "type": "similar"}
        assert build(minimal_document(related=[entry])).related == (entry,)


class TestFieldCoercion:
    def test_a_bare_string_reference_becomes_a_one_item_tuple(self) -> None:
        assert build(minimal_document(references="https://a.invalid")).references == (
            "https://a.invalid",
        )

    def test_a_reference_list_is_preserved_in_order(self) -> None:
        rule = build(minimal_document(references=["b", "a"]))
        assert rule.references == ("b", "a")

    def test_a_mapping_inside_a_string_list_is_refused(self) -> None:
        with pytest.raises(RuleLoadError, match=r"tags\[0\]"):
            build(minimal_document(tags=[{"attack": "execution"}]))

    def test_missing_string_lists_become_empty_tuples(self) -> None:
        document = minimal_document()
        assert build(document).tags == ()

    def test_non_string_scalars_are_stringified(self) -> None:
        assert build(minimal_document(tags=[1, 2])).tags == ("1", "2")

    def test_status_defaults_to_experimental(self) -> None:
        document = minimal_document()
        del document["status"]
        assert build(document).status is SigmaStatus.EXPERIMENTAL

    def test_an_unknown_status_is_refused(self) -> None:
        with pytest.raises(RuleLoadError):
            build(minimal_document(status="totally-made-up"))

    def test_level_defaults_to_medium(self) -> None:
        document = minimal_document()
        del document["level"]
        assert build(document).level is Severity.MEDIUM

    def test_an_unknown_level_is_refused(self) -> None:
        with pytest.raises(RuleLoadError):
            build(minimal_document(level="apocalyptic"))

    def test_level_is_parsed(self) -> None:
        assert build(minimal_document(level="high")).level is Severity.HIGH

    def test_description_is_stripped(self) -> None:
        assert build(minimal_document(description="  text  ")).description == "text"

    def test_a_missing_description_becomes_an_empty_string(self) -> None:
        document = minimal_document()
        del document["description"]
        assert build(document).description == ""

    def test_license_is_optional(self) -> None:
        assert build(minimal_document()).license is None

    def test_license_is_stripped(self) -> None:
        assert build(minimal_document(license=" MIT ")).license == "MIT"

    def test_an_empty_license_becomes_none(self) -> None:
        assert build(minimal_document(license="")).license is None

    def test_name_is_optional(self) -> None:
        assert build(minimal_document()).name is None

    def test_the_id_is_stripped(self) -> None:
        rule = build(minimal_document(id="  11111111-2222-4333-8444-555555555555  "))
        assert rule.rule_id == "11111111-2222-4333-8444-555555555555"

    def test_a_missing_id_becomes_an_empty_string(self) -> None:
        document = minimal_document()
        del document["id"]
        assert build(document).rule_id == ""

    def test_the_raw_document_is_retained(self) -> None:
        assert build(minimal_document()).raw["title"] == "Synthetic Rule"

    def test_logsource_fields_are_parsed(self) -> None:
        rule = build(minimal_document())
        assert rule.logsource.category == "process_creation"
        assert rule.logsource.product == "windows"

    def test_an_absent_logsource_yields_an_empty_one(self) -> None:
        document = minimal_document()
        del document["logsource"]
        rule = build(document)
        assert rule.logsource.category is None
        assert rule.logsource.product is None


class TestLoadingFromDisk:
    def test_a_real_rule_file_loads(self, tiny_config: LabConfig) -> None:
        path = next(iter(discover_rule_files(tiny_config)))
        rule = load_rule_file(path, config=tiny_config)
        assert rule.title == "Synthetic Process Launched From Staging Path"

    def test_the_raw_text_is_retained(self, tiny_config: LabConfig) -> None:
        path = next(iter(discover_rule_files(tiny_config)))
        assert "logsource:" in load_rule_file(path, config=tiny_config).raw_text

    def test_discovery_finds_the_only_rule(self, tiny_config: LabConfig) -> None:
        assert len(discover_rule_files(tiny_config)) == 1

    def test_discovery_is_recursive(self, tiny_config: LabConfig, tiny_project: Path) -> None:
        nested = tiny_project / "rules" / "a" / "b" / "c" / "nested_rule.yml"
        nested.parent.mkdir(parents=True, exist_ok=True)
        nested.write_text(SAMPLE_RULE_TEXT, encoding="utf-8")
        assert len(discover_rule_files(tiny_config)) == 2

    def test_discovery_ignores_non_yaml_files(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        (tiny_project / "rules" / "notes.md").write_text("ignored", encoding="utf-8")
        assert len(discover_rule_files(tiny_config)) == 1

    def test_discovery_accepts_a_yaml_extension(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        (tiny_project / "rules" / "other.yaml").write_text(SAMPLE_RULE_TEXT, encoding="utf-8")
        assert len(discover_rule_files(tiny_config)) == 2

    def test_discovery_of_a_missing_directory_is_empty(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        assert discover_rule_files(tiny_config, directory=tiny_project / "absent") == []

    def test_a_directory_of_rules_loads(self, tiny_config: LabConfig) -> None:
        outcome = load_rules(tiny_config)
        assert outcome.loaded_count == 1
        assert outcome.failure_count == 0

    def test_a_broken_rule_is_reported_not_raised(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        (tiny_project / "rules" / "broken.yml").write_text("title: [", encoding="utf-8")
        outcome = load_rules(tiny_config)
        assert outcome.loaded_count == 1
        assert outcome.failure_count == 1

    def test_the_failure_records_the_relative_path(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        (tiny_project / "rules" / "broken.yml").write_text("title: [", encoding="utf-8")
        path, message = load_rules(tiny_config).failures[0]
        assert path == "rules/broken.yml"
        assert message

    def test_a_non_mapping_document_is_a_failure(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        (tiny_project / "rules" / "list.yml").write_text("- one\n- two\n", encoding="utf-8")
        assert load_rules(tiny_config).failure_count == 1

    def test_an_oversized_rule_is_a_failure(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        oversized = "# " + ("x" * (tiny_config.limits.max_file_bytes + 10)) + "\n"
        (tiny_project / "rules" / "huge.yml").write_text(oversized, encoding="utf-8")
        assert load_rules(tiny_config).failure_count == 1

    def test_results_are_sorted_by_catalog_id(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        for name in ("zulu.yml", "alpha.yml", "mike.yml"):
            (tiny_project / "rules" / name).write_text(SAMPLE_RULE_TEXT, encoding="utf-8")
        ids = [rule.catalog_id for rule in load_rules(tiny_config).rules]
        assert ids == sorted(ids)

    def test_loading_an_empty_directory_yields_nothing(
        self, tiny_config: LabConfig, tiny_project: Path
    ) -> None:
        empty = tiny_project / "empty"
        empty.mkdir()
        outcome = load_rules(tiny_config, directory=empty)
        assert outcome.rules == ()
        assert outcome.failures == ()

    def test_a_missing_file_is_a_load_error(self, tiny_config: LabConfig) -> None:
        with pytest.raises(RuleLoadError):
            load_rule_file(tiny_config.rules_dir / "absent.yml", config=tiny_config)

    def test_discovery_never_leaves_the_project_root(self, tiny_config: LabConfig) -> None:
        root = tiny_config.root.resolve()
        assert all(root in path.resolve().parents for path in discover_rule_files(tiny_config))


class TestCorrelationBaseDocuments:
    def test_a_plain_rule_has_no_base_documents(self) -> None:
        assert correlation_base_documents(make_rule()) == {}

    def test_base_documents_are_keyed_by_name(self) -> None:
        base = minimal_document(name="base_rule")
        correlation = {"title": "C", "correlation": {"type": "event_count"}}
        rule = build([base, correlation])
        assert "base_rule" in correlation_base_documents(rule)

    def test_base_documents_are_keyed_by_id(self) -> None:
        base = minimal_document(name="base_rule")
        correlation = {"title": "C", "correlation": {"type": "event_count"}}
        rule = build([base, correlation])
        assert base["id"] in correlation_base_documents(rule)

    def test_the_correlation_document_is_not_a_base_document(self) -> None:
        base = minimal_document(name="base_rule")
        correlation = {
            "title": "C",
            "id": "44444444-5555-4666-8777-888888888888",
            "correlation": {"type": "event_count"},
        }
        resolved = correlation_base_documents(build([base, correlation]))
        assert correlation["id"] not in resolved

    def test_documents_without_detection_are_skipped(self) -> None:
        stub = {"title": "Stub", "name": "stub_only"}
        correlation = {"title": "C", "correlation": {"type": "event_count"}}
        assert "stub_only" not in correlation_base_documents(build([stub, correlation]))


class TestPySigmaIntegration:
    def test_the_status_is_cached_and_stable(self) -> None:
        assert pysigma_status() is pysigma_status()

    def test_the_status_reports_availability_as_a_bool(self) -> None:
        assert isinstance(pysigma_status().available, bool)

    def test_an_unavailable_backend_reports_an_error(self) -> None:
        status = pysigma_status()
        assert status.available or status.error

    def test_parsing_a_valid_rule_reports_a_result(self) -> None:
        result = parse_with_pysigma(SAMPLE_RULE_TEXT, source="sample.yml")
        assert result.attempted is pysigma_status().available

    def test_a_skipped_parse_explains_itself(self) -> None:
        result = parse_with_pysigma(SAMPLE_RULE_TEXT)
        if not result.attempted:
            assert "pySigma is not installed" in result.detail

    def test_a_successful_parse_counts_rules(self) -> None:
        result = parse_with_pysigma(SAMPLE_RULE_TEXT, source="sample.yml")
        if result.succeeded:
            assert result.rule_count >= 1

    def test_garbage_never_parses_successfully(self) -> None:
        assert parse_with_pysigma("::::not yaml::::").succeeded is False

    def test_the_result_serialises(self) -> None:
        payload = parse_with_pysigma(SAMPLE_RULE_TEXT).to_dict()
        assert set(payload) == {"attempted", "succeeded", "rule_count", "errors", "detail"}


class TestCatalogAssembly:
    def test_the_catalog_indexes_by_catalog_id(self) -> None:
        catalog = RuleCatalog([make_rule("a"), make_rule("b", rule_id="")])
        assert catalog.get("a") is not None

    def test_the_catalog_indexes_by_uuid_case_insensitively(self) -> None:
        rule = make_rule(rule_id="AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")
        catalog = RuleCatalog([rule])
        assert catalog.by_uuid("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee") is rule

    def test_duplicate_catalog_ids_produce_a_finding(self) -> None:
        catalog = RuleCatalog([make_rule("dup", rule_id="a"), make_rule("dup", rule_id="b")])
        codes = {finding.code for finding in catalog.uniqueness_findings()}
        assert "SDEL-CAT-001" in codes

    def test_duplicate_uuids_produce_a_finding(self) -> None:
        catalog = RuleCatalog([make_rule("one"), make_rule("two")])
        codes = {finding.code for finding in catalog.uniqueness_findings()}
        assert "SDEL-CAT-002" in codes

    def test_a_unique_catalog_has_no_findings(self) -> None:
        catalog = RuleCatalog([make_rule("one", rule_id="a"), make_rule("two", rule_id="b")])
        assert catalog.uniqueness_findings() == ()

    def test_resolution_accepts_every_identifier_form(self) -> None:
        rule = make_rule("alpha", rule_id="55555555-6666-4777-8888-999999999999", name="alpha_name")
        catalog = RuleCatalog([rule])
        assert catalog.resolve("alpha") is rule
        assert catalog.resolve("55555555-6666-4777-8888-999999999999") is rule
        assert catalog.resolve("alpha_name") is rule

    def test_resolving_an_empty_reference_returns_none(self, simple_catalog: RuleCatalog) -> None:
        assert simple_catalog.resolve("   ") is None

    def test_filtering_by_status_narrows_the_catalog(self) -> None:
        catalog = RuleCatalog(
            [
                make_rule("a", rule_id="a", status=SigmaStatus.EXPERIMENTAL),
                make_rule("b", rule_id="b", status=SigmaStatus.TEST),
            ]
        )
        assert len(catalog.filter(RuleFilter(status=SigmaStatus.TEST))) == 1

    def test_filtering_by_technique_uses_the_attack_tag(self, simple_catalog: RuleCatalog) -> None:
        assert len(simple_catalog.filter(technique="T1204.002")) == 1

    def test_filtering_by_an_absent_technique_returns_nothing(
        self, simple_catalog: RuleCatalog
    ) -> None:
        assert simple_catalog.filter(technique="T9999") == ()

    def test_free_text_filtering_searches_the_title(self, simple_catalog: RuleCatalog) -> None:
        assert len(simple_catalog.filter(text="synthetic")) == 1

    def test_the_summary_totals_match_the_rule_count(self, simple_catalog: RuleCatalog) -> None:
        assert simple_catalog.summary()["total"] == len(simple_catalog)

    def test_correlation_and_standard_partitions_are_complementary(self) -> None:
        catalog = RuleCatalog(
            [
                make_rule("a", rule_id="a"),
                make_rule("b", rule_id="b", is_correlation=True, correlation={"type": "x"}),
            ]
        )
        assert len(catalog.standard_rules()) + len(catalog.correlation_rules()) == len(catalog)


class TestRealCatalog:
    def test_the_real_catalog_is_not_empty(self, real_catalog: RuleCatalog) -> None:
        assert len(real_catalog) > 0

    def test_the_real_catalog_has_no_duplicates(self, real_catalog: RuleCatalog) -> None:
        assert real_catalog.uniqueness_findings() == ()

    def test_every_real_rule_has_a_uuid(self, real_catalog: RuleCatalog) -> None:
        assert all(rule.rule_id for rule in real_catalog)

    def test_every_real_rule_has_a_title(self, real_catalog: RuleCatalog) -> None:
        assert all(rule.title.strip() for rule in real_catalog)

    def test_every_real_rule_file_follows_the_naming_convention(
        self, real_catalog: RuleCatalog
    ) -> None:
        offenders = [
            rule.relative_path for rule in real_catalog if not is_valid_rule_filename(rule.path)
        ]
        assert offenders == []

    def test_no_real_rule_failed_to_load(self, real_config: LabConfig) -> None:
        assert load_rules(real_config).failures == ()
