"""ATT&CK Navigator layers, and the honesty conventions that bound them."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from conftest import make_rule, make_sidecar
from sigma_detection_engineering_lab.attack_catalog import AttackCatalog
from sigma_detection_engineering_lab.constants import COVERAGE_CAVEAT_BANNER
from sigma_detection_engineering_lab.coverage import build_coverage
from sigma_detection_engineering_lab.fixture_loader import FixtureSet
from sigma_detection_engineering_lab.metadata_loader import MetadataSet
from sigma_detection_engineering_lab.models import AttackMapping, CoverageReport
from sigma_detection_engineering_lab.navigator import (
    DEFAULT_DOMAIN,
    GRADIENT_COLORS,
    LAYER_VERSION,
    LEGEND,
    NAVIGATOR_VERSION,
    build_and_write,
    build_layer,
    layer_summary,
    render_layer,
    unverified_techniques,
    write_layer,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog

EMPTY_FIXTURES = FixtureSet(cases=(), sequences=())


def coverage_for(*mappings: tuple[str, tuple[str, ...]]) -> tuple[CoverageReport, MetadataSet]:
    """Build a coverage report whose technique counts come from ``mappings``."""
    rules = []
    sidecars = []
    for index, (catalog_id, techniques) in enumerate(mappings):
        rule_id = f"{index:08d}-0000-4000-8000-000000000000"
        rules.append(make_rule(catalog_id=catalog_id, rule_id=rule_id))
        sidecars.append(
            make_sidecar(
                catalog_id=catalog_id,
                rule_id=rule_id,
                attack_mapping=AttackMapping(techniques=techniques, tactics=("TA0002",)),
            )
        )
    metadata = MetadataSet(sidecars=tuple(sidecars))
    coverage = build_coverage(RuleCatalog(rules), metadata, EMPTY_FIXTURES)
    return coverage, metadata


@pytest.fixture
def single_technique() -> tuple[CoverageReport, MetadataSet]:
    return coverage_for(("SDEL-A", ("T1059.001",)))


class TestLayerShape:
    def test_the_layer_version_is_declared(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert layer["versions"]["layer"] == LAYER_VERSION

    def test_the_layer_version_is_four_five(self) -> None:
        assert LAYER_VERSION == "4.5"

    def test_the_navigator_version_is_declared(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert layer["versions"]["navigator"] == NAVIGATOR_VERSION

    def test_an_unavailable_attack_version_is_labelled_unknown(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert layer["versions"]["attack"] == "unknown"

    def test_the_domain_falls_back_to_enterprise(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        assert build_layer(coverage, metadata, AttackCatalog())["domain"] == DEFAULT_DOMAIN

    def test_the_domain_can_be_overridden(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog(), domain="mobile-attack")
        assert layer["domain"] == "mobile-attack"

    def test_the_name_can_be_set(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        assert build_layer(coverage, metadata, AttackCatalog(), name="mine")["name"] == "mine"

    def test_a_gradient_is_present(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert layer["gradient"]["colors"] == list(GRADIENT_COLORS)

    def test_the_gradient_maximum_follows_the_highest_score(self) -> None:
        coverage, metadata = coverage_for(("SDEL-A", ("T1059.001",)), ("SDEL-B", ("T1059.001",)))
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert layer["gradient"]["maxValue"] == 2

    def test_an_empty_layer_has_a_gradient_maximum_of_one(self) -> None:
        coverage = build_coverage(RuleCatalog([]), MetadataSet(sidecars=()), EMPTY_FIXTURES)
        layer = build_layer(coverage, MetadataSet(sidecars=()), AttackCatalog())
        assert layer["gradient"]["maxValue"] == 1

    def test_the_legend_is_emitted(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert len(layer["legendItems"]) == len(LEGEND)

    def test_the_legend_labels_speak_of_rule_counts(self) -> None:
        assert all("rule" in label for label, _ in LEGEND)

    def test_the_layout_is_declared(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        assert build_layer(coverage, metadata, AttackCatalog())["layout"]["showID"] is True

    def test_disabled_techniques_are_not_hidden(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        assert build_layer(coverage, metadata, AttackCatalog())["hideDisabled"] is False


class TestHonesty:
    def test_the_default_description_carries_the_caveat(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert COVERAGE_CAVEAT_BANNER in layer["description"]

    def test_the_default_description_denies_confidence_scoring(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert "not a measure of" in layer["description"]

    def test_a_custom_description_replaces_the_default(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog(), description="mine")
        assert layer["description"] == "mine"

    def test_the_caveat_is_in_the_layer_metadata(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        values = {entry["name"]: entry["value"] for entry in layer["metadata"]}
        assert values["caveat"] == COVERAGE_CAVEAT_BANNER

    def test_the_generator_is_named(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        values = {entry["name"]: entry["value"] for entry in layer["metadata"]}
        assert "sigma-detection-engineering-lab" in values["generator"]

    def test_an_unverified_catalog_is_declared_as_such(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        values = {entry["name"]: entry["value"] for entry in layer["metadata"]}
        assert values["verified_against"] == "unverified"

    def test_the_generation_time_is_recorded(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        values = {entry["name"]: entry["value"] for entry in layer["metadata"]}
        assert values["generated_at"] == coverage.generated_at

    def test_each_technique_comment_carries_the_caveat(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert COVERAGE_CAVEAT_BANNER in layer["techniques"][0]["comment"]

    def test_each_technique_comment_states_the_rule_count(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert "1 rule(s)" in layer["techniques"][0]["comment"]


class TestVerification:
    def test_an_unverifiable_technique_is_dropped(self, real_attack: AttackCatalog) -> None:
        coverage, metadata = coverage_for(("SDEL-A", ("T9999.999",)))
        layer = build_layer(coverage, metadata, real_attack)
        assert layer["techniques"] == []

    def test_a_dropped_technique_is_recorded_in_the_metadata(
        self, real_attack: AttackCatalog
    ) -> None:
        coverage, metadata = coverage_for(("SDEL-A", ("T9999.999",)))
        layer = build_layer(coverage, metadata, real_attack)
        names = {entry["name"] for entry in layer["metadata"]}
        assert "omitted_unverified_techniques" in names

    def test_nothing_is_recorded_when_nothing_is_dropped(self, real_attack: AttackCatalog) -> None:
        target = sorted(real_attack.techniques)[0]
        coverage, metadata = coverage_for(("SDEL-A", (target,)))
        layer = build_layer(coverage, metadata, real_attack)
        names = {entry["name"] for entry in layer["metadata"]}
        assert "omitted_unverified_techniques" not in names

    def test_an_unavailable_catalog_emits_everything(self) -> None:
        coverage, metadata = coverage_for(("SDEL-A", ("T9999.999",)))
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert len(layer["techniques"]) == 1

    def test_a_verified_technique_is_emitted(self, real_attack: AttackCatalog) -> None:
        target = sorted(real_attack.techniques)[0]
        coverage, metadata = coverage_for(("SDEL-A", (target,)))
        layer = build_layer(coverage, metadata, real_attack)
        assert layer["techniques"][0]["techniqueID"] == target

    def test_unverified_techniques_are_listed(self, real_attack: AttackCatalog) -> None:
        coverage, _ = coverage_for(("SDEL-A", ("T9999.999",)))
        assert unverified_techniques(coverage, real_attack) == ("T9999.999",)

    def test_an_unavailable_catalog_makes_everything_unverified(self) -> None:
        coverage, _ = coverage_for(("SDEL-A", ("T1059.001",)))
        assert unverified_techniques(coverage, AttackCatalog()) == ("T1059.001",)

    def test_a_verified_technique_is_not_listed(self, real_attack: AttackCatalog) -> None:
        target = sorted(real_attack.techniques)[0]
        coverage, _ = coverage_for(("SDEL-A", (target,)))
        assert unverified_techniques(coverage, real_attack) == ()


class TestTechniqueEntries:
    def test_the_score_is_the_rule_count(self) -> None:
        coverage, metadata = coverage_for(("SDEL-A", ("T1059.001",)), ("SDEL-B", ("T1059.001",)))
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert layer["techniques"][0]["score"] == 2

    @pytest.mark.parametrize(
        ("rule_count", "color"),
        [(1, "#deebf7"), (2, "#9ecae1"), (3, "#3182bd"), (5, "#3182bd")],
    )
    def test_the_colour_encodes_the_rule_count(self, rule_count: int, color: str) -> None:
        coverage, metadata = coverage_for(
            *[(f"SDEL-{index}", ("T1059.001",)) for index in range(rule_count)]
        )
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert layer["techniques"][0]["color"] == color

    def test_the_identifier_is_upper_cased(self) -> None:
        coverage, metadata = coverage_for(("SDEL-A", ("t1059.001",)))
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert layer["techniques"][0]["techniqueID"] == "T1059.001"

    def test_a_subtechnique_asks_navigator_to_expand(self) -> None:
        coverage, metadata = coverage_for(("SDEL-A", ("T1059.001",)))
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert layer["techniques"][0]["showSubtechniques"] is True

    def test_a_parent_technique_does_not(self) -> None:
        coverage, metadata = coverage_for(("SDEL-A", ("T1059",)))
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert layer["techniques"][0]["showSubtechniques"] is False

    def test_the_contributing_rules_are_named(self) -> None:
        coverage, metadata = coverage_for(("SDEL-A", ("T1059.001",)))
        layer = build_layer(coverage, metadata, AttackCatalog())
        values = {e["name"]: e["value"] for e in layer["techniques"][0]["metadata"]}
        assert values["rules"] == "SDEL-A"

    def test_contributing_rules_are_sorted(self) -> None:
        coverage, metadata = coverage_for(("SDEL-Z", ("T1059.001",)), ("SDEL-A", ("T1059.001",)))
        layer = build_layer(coverage, metadata, AttackCatalog())
        values = {e["name"]: e["value"] for e in layer["techniques"][0]["metadata"]}
        assert values["rules"] == "SDEL-A, SDEL-Z"

    def test_techniques_are_sorted_by_identifier(self) -> None:
        coverage, metadata = coverage_for(("SDEL-A", ("T1204.002", "T1059.001")))
        layer = build_layer(coverage, metadata, AttackCatalog())
        ids = [entry["techniqueID"] for entry in layer["techniques"]]
        assert ids == sorted(ids)

    def test_every_technique_is_enabled(self) -> None:
        coverage, metadata = coverage_for(("SDEL-A", ("T1059.001",)))
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert all(entry["enabled"] for entry in layer["techniques"])

    def test_the_rule_count_is_in_the_entry_metadata(self) -> None:
        coverage, metadata = coverage_for(("SDEL-A", ("T1059.001",)))
        layer = build_layer(coverage, metadata, AttackCatalog())
        values = {e["name"]: e["value"] for e in layer["techniques"][0]["metadata"]}
        assert values["rule_count"] == "1"


class TestRendering:
    def test_the_layer_renders_as_json(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        text = render_layer(build_layer(coverage, metadata, AttackCatalog()))
        assert json.loads(text)["versions"]["layer"] == LAYER_VERSION

    def test_rendering_is_deterministic(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert render_layer(layer) == render_layer(layer)

    def test_keys_are_sorted(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        text = render_layer(build_layer(coverage, metadata, AttackCatalog()))
        keys = [line.strip().split('"')[1] for line in text.splitlines() if line.startswith('  "')]
        assert keys == sorted(keys)

    def test_the_output_ends_with_a_newline(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        assert render_layer(build_layer(coverage, metadata, AttackCatalog())).endswith("\n")

    def test_the_indent_is_configurable(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert len(render_layer(layer, indent=0)) < len(render_layer(layer, indent=4))


class TestWriting:
    def test_the_file_is_created(self, tmp_path: Path, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert write_layer(layer, tmp_path / "layer.json").is_file()

    def test_parent_directories_are_created(self, tmp_path: Path, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert write_layer(layer, tmp_path / "a" / "b" / "layer.json").is_file()

    def test_line_endings_are_lf(self, tmp_path: Path, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        target = write_layer(layer, tmp_path / "layer.json")
        assert b"\r\n" not in target.read_bytes()

    def test_the_written_file_parses(self, tmp_path: Path, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        target = write_layer(layer, tmp_path / "layer.json")
        assert json.loads(target.read_text(encoding="utf-8"))["name"]

    def test_build_and_write_does_both(self, tmp_path: Path, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        target = build_and_write(coverage, metadata, AttackCatalog(), tmp_path / "layer.json")
        assert json.loads(target.read_text(encoding="utf-8"))["techniques"]

    def test_build_and_write_accepts_a_catalog(self, tmp_path: Path, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        target = build_and_write(
            coverage,
            metadata,
            AttackCatalog(),
            tmp_path / "layer.json",
            catalog=RuleCatalog([make_rule()]),
        )
        assert (
            "1 original Sigma rule(s)"
            in json.loads(target.read_text(encoding="utf-8"))["description"]
        )


class TestSummary:
    def test_the_technique_count_is_reported(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert layer_summary(layer)["technique_count"] == 1

    def test_the_layer_version_is_reported(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert layer_summary(layer)["layer_version"] == LAYER_VERSION

    def test_the_domain_is_reported(self, single_technique) -> None:  # type: ignore[no-untyped-def]
        coverage, metadata = single_technique
        layer = build_layer(coverage, metadata, AttackCatalog())
        assert layer_summary(layer)["domain"] == DEFAULT_DOMAIN

    def test_an_empty_mapping_summarises_safely(self) -> None:
        assert layer_summary({})["technique_count"] == 0


class TestRealLayer:
    @pytest.fixture(scope="session")
    def real_layer(
        self,
        real_catalog: RuleCatalog,
        real_metadata: MetadataSet,
        real_fixtures: FixtureSet,
        real_attack: AttackCatalog,
    ) -> dict[str, Any]:
        coverage = build_coverage(real_catalog, real_metadata, real_fixtures)
        return build_layer(coverage, real_metadata, real_attack, catalog=real_catalog)

    def test_the_real_layer_has_techniques(self, real_layer: dict[str, Any]) -> None:
        assert real_layer["techniques"]

    def test_the_real_layer_omits_nothing(self, real_layer: dict[str, Any]) -> None:
        names = {entry["name"] for entry in real_layer["metadata"]}
        assert "omitted_unverified_techniques" not in names

    def test_the_real_layer_names_the_attack_version(self, real_layer: dict[str, Any]) -> None:
        assert real_layer["versions"]["attack"] != "unknown"

    def test_the_real_layer_renders(self, real_layer: dict[str, Any]) -> None:
        assert json.loads(render_layer(real_layer))["domain"]

    def test_the_real_layer_writes(self, real_layer: dict[str, Any], tmp_path: Path) -> None:
        target = write_layer(real_layer, tmp_path / "real.json")
        assert json.loads(target.read_text(encoding="utf-8"))["techniques"]

    def test_every_real_technique_scores_at_least_one(self, real_layer: dict[str, Any]) -> None:
        assert all(entry["score"] >= 1 for entry in real_layer["techniques"])
