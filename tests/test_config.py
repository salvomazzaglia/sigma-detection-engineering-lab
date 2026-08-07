"""Tests for configuration loading and bounds checking.

Configuration determines the safety limits applied to untrusted rule content, so
a mistaken edit must fail loudly rather than quietly disable a protection.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest

from conftest import MINIMAL_CONFIG, build_project, write_json
from sigma_detection_engineering_lab.config import (
    BOOLEAN_LIMITS,
    CONFIG_DIRECTORY,
    DEFAULT_EVALUATOR_PROFILE,
    DEFAULT_PROFILE,
    LIMIT_BOUNDS,
    REQUIRED_PATH_KEYS,
    BackendConfig,
    ConversionConfig,
    LabConfig,
    Limits,
    ProjectDirectories,
    load_config,
    load_conversion_config,
    load_evaluator_profile,
    load_upstream_versions,
    read_config_json,
    validate_limits,
)
from sigma_detection_engineering_lab.errors import ConfigError
from sigma_detection_engineering_lab.statuses import Maturity, SigmaStatus


def config_with(tmp_path: Path, **overrides: Any) -> Path:
    """Materialise a project whose default config carries ``overrides``."""
    payload = copy.deepcopy(MINIMAL_CONFIG)
    payload.update(overrides)
    return build_project(tmp_path / "project", config=payload)


def config_missing(tmp_path: Path, key: str) -> Path:
    payload = copy.deepcopy(MINIMAL_CONFIG)
    payload.pop(key, None)
    return build_project(tmp_path / "project", config=payload)


class TestValidateLimits:
    def valid(self, **overrides: Any) -> dict[str, Any]:
        values = dict(MINIMAL_CONFIG["limits"])
        values.update(overrides)
        return values

    def test_valid_limits_build_a_limits_object(self) -> None:
        assert isinstance(validate_limits(self.valid()), Limits)

    def test_values_are_carried_through(self) -> None:
        limits = validate_limits(self.valid(max_yaml_depth=16))
        assert limits.max_yaml_depth == 16

    @pytest.mark.parametrize("key", sorted(LIMIT_BOUNDS))
    def test_every_integer_limit_is_required(self, key: str) -> None:
        values = self.valid()
        del values[key]
        with pytest.raises(ConfigError, match=f"missing required limit '{key}'"):
            validate_limits(values)

    @pytest.mark.parametrize("key", sorted(LIMIT_BOUNDS))
    def test_below_minimum_is_refused(self, key: str) -> None:
        minimum = LIMIT_BOUNDS[key][0]
        with pytest.raises(ConfigError, match="outside accepted range"):
            validate_limits(self.valid(**{key: minimum - 1}))

    @pytest.mark.parametrize("key", sorted(LIMIT_BOUNDS))
    def test_above_maximum_is_refused(self, key: str) -> None:
        maximum = LIMIT_BOUNDS[key][1]
        with pytest.raises(ConfigError, match="outside accepted range"):
            validate_limits(self.valid(**{key: maximum + 1}))

    @pytest.mark.parametrize("key", sorted(LIMIT_BOUNDS))
    def test_boundary_values_are_accepted(self, key: str) -> None:
        minimum, maximum = LIMIT_BOUNDS[key]
        assert validate_limits(self.valid(**{key: minimum}))
        assert validate_limits(self.valid(**{key: maximum}))

    def test_boolean_is_not_accepted_as_an_integer(self) -> None:
        with pytest.raises(ConfigError, match="must be an integer"):
            validate_limits(self.valid(max_yaml_depth=True))

    def test_string_is_not_accepted_as_an_integer(self) -> None:
        with pytest.raises(ConfigError, match="must be an integer"):
            validate_limits(self.valid(max_yaml_depth="32"))

    def test_float_is_not_accepted_as_an_integer(self) -> None:
        with pytest.raises(ConfigError, match="must be an integer"):
            validate_limits(self.valid(max_yaml_depth=32.0))

    def test_unknown_key_is_refused(self) -> None:
        with pytest.raises(ConfigError, match="unknown limit keys"):
            validate_limits(self.valid(max_yaml_dept=32))

    def test_missing_boolean_limit_is_refused(self) -> None:
        values = self.valid()
        del values["allow_symlinks"]
        with pytest.raises(ConfigError, match="missing required limit"):
            validate_limits(values)

    def test_non_boolean_symlink_flag_is_refused(self) -> None:
        with pytest.raises(ConfigError, match="must be a boolean"):
            validate_limits(self.valid(allow_symlinks="no"))

    def test_enabling_symlinks_is_refused_outright(self) -> None:
        with pytest.raises(ConfigError, match="symlink following is not permitted"):
            validate_limits(self.valid(allow_symlinks=True))

    def test_label_appears_in_the_error(self) -> None:
        with pytest.raises(ConfigError, match=re.escape("custom.limits")):
            validate_limits({}, label="custom.limits")

    def test_boolean_limit_registry(self) -> None:
        assert BOOLEAN_LIMITS == ("allow_symlinks",)


class TestLimits:
    def test_yaml_limits_projection(self) -> None:
        limits = Limits(max_yaml_depth=12, max_yaml_nodes=99, max_yaml_aliases=2)
        projected = limits.yaml_limits()
        assert projected.max_depth == 12
        assert projected.max_nodes == 99
        assert projected.max_aliases == 2

    def test_yaml_limits_carries_the_file_bound(self) -> None:
        assert Limits(max_file_bytes=2048).yaml_limits().max_file_bytes == 2048

    def test_to_dict_covers_every_limit(self) -> None:
        payload = Limits().to_dict()
        assert set(payload) == set(LIMIT_BOUNDS) | set(BOOLEAN_LIMITS)

    def test_defaults_forbid_symlinks(self) -> None:
        assert Limits().allow_symlinks is False


class TestProjectDirectories:
    def test_to_dict_covers_every_required_key(self) -> None:
        assert set(ProjectDirectories().to_dict()) == set(REQUIRED_PATH_KEYS)

    def test_defaults_are_relative(self) -> None:
        assert all(not value.startswith("/") for value in ProjectDirectories().to_dict().values())


class TestLoadConfig:
    def test_loads_a_valid_project(self, tmp_path: Path) -> None:
        config = load_config(config_with(tmp_path))
        assert config.project_name == "sdel-test-project"

    def test_records_the_source_path(self, tmp_path: Path) -> None:
        root = config_with(tmp_path)
        assert load_config(root).source_path == root / "config" / "default.config.json"

    def test_profile_defaults_to_default(self, tmp_path: Path) -> None:
        assert load_config(config_with(tmp_path)).profile == DEFAULT_PROFILE

    def test_root_is_absolute(self, tmp_path: Path) -> None:
        assert load_config(config_with(tmp_path)).root.is_absolute()

    def test_missing_file_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / "empty").mkdir()
        with pytest.raises(ConfigError, match="configuration file not found"):
            load_config(tmp_path / "empty")

    def test_invalid_json_is_refused(self, tmp_path: Path) -> None:
        root = tmp_path / "project"
        (root / "config").mkdir(parents=True)
        (root / "config" / "default.config.json").write_text("{ nope", encoding="utf-8")
        with pytest.raises(ConfigError, match="invalid JSON"):
            load_config(root)

    def test_non_object_root_is_refused(self, tmp_path: Path) -> None:
        root = tmp_path / "project"
        (root / "config").mkdir(parents=True)
        (root / "config" / "default.config.json").write_text("[]", encoding="utf-8")
        with pytest.raises(ConfigError, match="must be an object"):
            load_config(root)

    @pytest.mark.parametrize("profile", ["", "../evil", "a/b", "a\\b", ".."])
    def test_unsafe_profile_names_are_refused(self, tmp_path: Path, profile: str) -> None:
        with pytest.raises(ConfigError, match="invalid configuration profile"):
            load_config(tmp_path, profile=profile)

    def test_missing_schema_version_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="'schema_version'"):
            load_config(config_missing(tmp_path, "schema_version"))

    def test_missing_project_name_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="'project_name'"):
            load_config(config_missing(tmp_path, "project_name"))

    def test_missing_path_key_is_refused(self, tmp_path: Path) -> None:
        payload = copy.deepcopy(MINIMAL_CONFIG)
        del payload["paths"]["rules"]
        with pytest.raises(ConfigError, match="missing required keys"):
            load_config(build_project(tmp_path / "p", config=payload))

    def test_absolute_directory_is_refused(self, tmp_path: Path) -> None:
        payload = copy.deepcopy(MINIMAL_CONFIG)
        payload["paths"]["rules"] = "/etc"
        with pytest.raises(ConfigError, match="must be a relative path"):
            load_config(build_project(tmp_path / "p", config=payload))

    def test_traversal_in_a_directory_is_refused(self, tmp_path: Path) -> None:
        payload = copy.deepcopy(MINIMAL_CONFIG)
        payload["paths"]["rules"] = "../rules"
        with pytest.raises(ConfigError, match="must be a relative path"):
            load_config(build_project(tmp_path / "p", config=payload))

    def test_empty_directory_name_is_refused(self, tmp_path: Path) -> None:
        payload = copy.deepcopy(MINIMAL_CONFIG)
        payload["paths"]["rules"] = "  "
        with pytest.raises(ConfigError, match="non-empty string"):
            load_config(build_project(tmp_path / "p", config=payload))

    def test_backslashes_in_a_directory_are_normalised(self, tmp_path: Path) -> None:
        payload = copy.deepcopy(MINIMAL_CONFIG)
        payload["paths"]["metadata"] = "metadata\\rules"
        config = load_config(build_project(tmp_path / "p", config=payload))
        assert config.directories.metadata == "metadata/rules"

    def test_missing_authors_block_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="at least one author"):
            load_config(config_missing(tmp_path, "authors"))

    def test_non_list_author_block_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="array of strings"):
            load_config(config_with(tmp_path, authors={"required": "someone"}))

    def test_non_string_author_entry_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="must be a string"):
            load_config(config_with(tmp_path, authors={"required": [1]}))

    def test_empty_license_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="'license'"):
            load_config(config_with(tmp_path, license=""))

    def test_unknown_status_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            load_config(config_with(tmp_path, allowed_sigma_statuses=["nonsense"]))

    def test_empty_allowed_statuses_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="must not be empty"):
            load_config(config_with(tmp_path, allowed_sigma_statuses=[]))

    def test_status_both_allowed_and_blocked_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="both allowed and blocked"):
            load_config(
                config_with(
                    tmp_path,
                    allowed_sigma_statuses=["experimental", "test"],
                    blocked_sigma_statuses_main_catalog=["test"],
                )
            )

    def test_unknown_maturity_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            load_config(config_with(tmp_path, allowed_maturity=["nonsense"]))

    def test_empty_maturity_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="must not be empty"):
            load_config(config_with(tmp_path, allowed_maturity=[]))

    def test_empty_banner_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="synthetic_banner"):
            load_config(config_with(tmp_path, synthetic_banner=""))

    def test_non_boolean_demo_mode_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="demo_mode"):
            load_config(config_with(tmp_path, demo_mode="yes"))

    def test_statuses_are_parsed_into_enums(self, tmp_path: Path) -> None:
        config = load_config(config_with(tmp_path))
        assert SigmaStatus.EXPERIMENTAL in config.allowed_sigma_statuses

    def test_maturity_is_parsed_into_enums(self, tmp_path: Path) -> None:
        config = load_config(config_with(tmp_path))
        assert Maturity.EXPERIMENTAL in config.allowed_maturity

    def test_raw_document_is_retained(self, tmp_path: Path) -> None:
        assert load_config(config_with(tmp_path)).raw["project_name"] == "sdel-test-project"


class TestLabConfigResolution:
    def test_rules_dir_resolves_under_the_root(self, tiny_config: LabConfig) -> None:
        assert tiny_config.rules_dir == tiny_config.root / "rules"

    @pytest.mark.parametrize("kind", sorted(REQUIRED_PATH_KEYS))
    def test_every_directory_key_resolves(self, tiny_config: LabConfig, kind: str) -> None:
        assert tiny_config.resolve(kind).is_absolute()

    def test_unknown_directory_key_is_refused(self, tiny_config: LabConfig) -> None:
        with pytest.raises(ConfigError, match="unknown directory key"):
            tiny_config.resolve("nonexistent")

    def test_error_lists_the_known_keys(self, tiny_config: LabConfig) -> None:
        with pytest.raises(ConfigError, match="rules"):
            tiny_config.resolve("nonexistent")

    def test_config_dir_points_at_the_config_directory(self, tiny_config: LabConfig) -> None:
        assert tiny_config.config_dir == tiny_config.root / CONFIG_DIRECTORY

    def test_named_properties_agree_with_resolve(self, tiny_config: LabConfig) -> None:
        assert tiny_config.metadata_dir == tiny_config.resolve("metadata")
        assert tiny_config.fixtures_dir == tiny_config.resolve("fixtures")
        assert tiny_config.attack_data_dir == tiny_config.resolve("attack_data")
        assert tiny_config.schemas_dir == tiny_config.resolve("schemas")
        assert tiny_config.examples_dir == tiny_config.resolve("examples")
        assert tiny_config.temp_dir == tiny_config.resolve("temp_output")

    def test_to_dict_is_json_serialisable(self, tiny_config: LabConfig) -> None:
        assert json.loads(json.dumps(tiny_config.to_dict()))["project_name"]

    def test_to_dict_renders_statuses_as_strings(self, tiny_config: LabConfig) -> None:
        assert all(
            isinstance(item, str) for item in tiny_config.to_dict()["allowed_sigma_statuses"]
        )


class TestRealProjectConfig:
    def test_real_config_loads(self, real_config: LabConfig) -> None:
        assert real_config.project_name

    def test_real_config_forbids_symlinks(self, real_config: LabConfig) -> None:
        assert real_config.limits.allow_symlinks is False

    def test_real_config_forbids_yaml_aliases(self, real_config: LabConfig) -> None:
        assert real_config.limits.max_yaml_aliases == 0

    def test_real_config_declares_authors(self, real_config: LabConfig) -> None:
        assert real_config.required_authors

    def test_real_config_directories_exist(self, real_config: LabConfig) -> None:
        assert real_config.rules_dir.is_dir()

    def test_real_config_blocks_stable_status(self, real_config: LabConfig) -> None:
        assert SigmaStatus.STABLE in real_config.blocked_sigma_statuses

    def test_real_config_banner_mentions_synthetic_data(self, real_config: LabConfig) -> None:
        assert "synthetic" in real_config.synthetic_banner.lower()


class TestEvaluatorProfile:
    def test_absent_file_falls_back_to_the_built_in_default(self, tiny_config: LabConfig) -> None:
        assert load_evaluator_profile(tiny_config) is DEFAULT_EVALUATOR_PROFILE

    def test_default_profile_is_case_insensitive(self) -> None:
        assert DEFAULT_EVALUATOR_PROFILE.default_case_sensitive is False

    def test_default_profile_rejects_catastrophic_patterns(self) -> None:
        assert DEFAULT_EVALUATOR_PROFILE.reject_catastrophic_patterns is True

    def test_default_profile_lists_the_supported_modifiers(self) -> None:
        assert "contains" in DEFAULT_EVALUATOR_PROFILE.supported_modifiers

    def test_default_profile_lists_the_correlation_types(self) -> None:
        assert "temporal_ordered" in DEFAULT_EVALUATOR_PROFILE.correlation_types

    def test_default_profile_marks_aggregations_unsupported(self) -> None:
        assert "aggregations" in DEFAULT_EVALUATOR_PROFILE.unsupported

    def test_profile_to_dict_sorts_collections(self) -> None:
        payload = DEFAULT_EVALUATOR_PROFILE.to_dict()
        assert payload["supported_modifiers"] == sorted(payload["supported_modifiers"])

    def test_loads_a_present_profile(self, tmp_path: Path) -> None:
        root = build_project(
            tmp_path / "p",
            evaluator_profile={
                "name": "custom-matcher",
                "supported_modifiers": ["contains"],
                "case_handling": {"default": "case_sensitive"},
                "regex": {"max_length": 64, "reject_catastrophic_patterns": False},
            },
        )
        profile = load_evaluator_profile(load_config(root))
        assert profile.name == "custom-matcher"
        assert profile.default_case_sensitive is True
        assert profile.max_regex_length == 64
        assert profile.reject_catastrophic_patterns is False

    def test_bad_case_handling_is_refused(self, tmp_path: Path) -> None:
        root = build_project(
            tmp_path / "p", evaluator_profile={"case_handling": {"default": "sometimes"}}
        )
        with pytest.raises(ConfigError, match=re.escape("case_handling.default")):
            load_evaluator_profile(load_config(root))

    def test_non_integer_regex_length_is_refused(self, tmp_path: Path) -> None:
        root = build_project(tmp_path / "p", evaluator_profile={"regex": {"max_length": "64"}})
        with pytest.raises(ConfigError, match="max_length"):
            load_evaluator_profile(load_config(root))

    def test_out_of_range_regex_length_is_refused(self, tmp_path: Path) -> None:
        root = build_project(tmp_path / "p", evaluator_profile={"regex": {"max_length": 99999}})
        with pytest.raises(ConfigError, match="outside range"):
            load_evaluator_profile(load_config(root))

    def test_non_boolean_catastrophic_flag_is_refused(self, tmp_path: Path) -> None:
        root = build_project(
            tmp_path / "p",
            evaluator_profile={"regex": {"reject_catastrophic_patterns": "yes"}},
        )
        with pytest.raises(ConfigError, match="reject_catastrophic_patterns"):
            load_evaluator_profile(load_config(root))

    def test_empty_name_is_refused(self, tmp_path: Path) -> None:
        root = build_project(tmp_path / "p", evaluator_profile={"name": ""})
        with pytest.raises(ConfigError, match="'name'"):
            load_evaluator_profile(load_config(root))

    def test_empty_modifier_list_falls_back_to_the_default(self, tmp_path: Path) -> None:
        root = build_project(tmp_path / "p", evaluator_profile={"supported_modifiers": []})
        profile = load_evaluator_profile(load_config(root))
        assert profile.supported_modifiers == DEFAULT_EVALUATOR_PROFILE.supported_modifiers

    def test_real_project_profile_loads(self, real_config: LabConfig) -> None:
        assert load_evaluator_profile(real_config).name


class TestConversionConfig:
    def test_absent_file_yields_an_empty_configuration(self, tiny_config: LabConfig) -> None:
        assert load_conversion_config(tiny_config).backends == ()

    def test_backends_are_parsed(self, tmp_path: Path) -> None:
        root = build_project(
            tmp_path / "p",
            conversion_backends={
                "backends": {
                    "splunk": {
                        "enabled": True,
                        "package": "pysigma-backend-splunk",
                        "version": "1.0.0",
                        "backend_class": "sigma.backends.splunk.SplunkBackend",
                        "dialect": "default",
                        "demonstration_banner": "demo only",
                    }
                },
                "correlation_conversion": {"supported_in_v1": False, "notes": "n/a"},
            },
        )
        conversion = load_conversion_config(load_config(root))
        assert conversion.get("splunk") is not None
        assert conversion.correlation_supported is False

    def test_disabled_backends_are_excluded_from_enabled(self, tmp_path: Path) -> None:
        root = build_project(
            tmp_path / "p",
            conversion_backends={
                "backends": {
                    "a": {"enabled": False, "backend_class": "x.Y"},
                    "b": {"enabled": True, "backend_class": "x.Z"},
                }
            },
        )
        conversion = load_conversion_config(load_config(root))
        assert [backend.key for backend in conversion.enabled_backends()] == ["b"]

    def test_backend_entry_must_be_an_object(self, tmp_path: Path) -> None:
        root = build_project(
            tmp_path / "p", conversion_backends={"backends": {"a": "not-an-object"}}
        )
        with pytest.raises(ConfigError, match="must be an object"):
            load_conversion_config(load_config(root))

    def test_backend_class_must_be_dotted(self, tmp_path: Path) -> None:
        root = build_project(
            tmp_path / "p", conversion_backends={"backends": {"a": {"backend_class": "Nope"}}}
        )
        with pytest.raises(ConfigError, match="dotted import path"):
            load_conversion_config(load_config(root))

    def test_enabled_must_be_a_boolean(self, tmp_path: Path) -> None:
        root = build_project(
            tmp_path / "p",
            conversion_backends={"backends": {"a": {"backend_class": "x.Y", "enabled": "yes"}}},
        )
        with pytest.raises(ConfigError, match="enabled"):
            load_conversion_config(load_config(root))

    def test_pipeline_must_be_a_string_or_null(self, tmp_path: Path) -> None:
        root = build_project(
            tmp_path / "p",
            conversion_backends={"backends": {"a": {"backend_class": "x.Y", "pipeline": 5}}},
        )
        with pytest.raises(ConfigError, match="pipeline"):
            load_conversion_config(load_config(root))

    def test_correlation_support_flag_must_be_boolean(self, tmp_path: Path) -> None:
        root = build_project(
            tmp_path / "p",
            conversion_backends={"correlation_conversion": {"supported_in_v1": "no"}},
        )
        with pytest.raises(ConfigError, match="supported_in_v1"):
            load_conversion_config(load_config(root))

    def test_unknown_backend_lookup_returns_none(self) -> None:
        assert ConversionConfig().get("nope") is None

    def test_backend_module_and_class_split(self) -> None:
        backend = BackendConfig(
            key="splunk",
            enabled=True,
            package="p",
            version="1",
            backend_class="sigma.backends.splunk.SplunkBackend",
            dialect="default",
            demonstration_banner="demo",
        )
        assert backend.module_path == "sigma.backends.splunk"
        assert backend.class_name == "SplunkBackend"

    def test_backend_to_dict_round_trips(self) -> None:
        backend = BackendConfig("k", True, "p", "1", "a.B", "d", "banner")
        assert backend.to_dict()["backend_class"] == "a.B"

    def test_conversion_to_dict_is_json_serialisable(self) -> None:
        assert json.loads(json.dumps(ConversionConfig().to_dict())) == {
            "backends": [],
            "correlation_supported": False,
            "notes": "",
        }

    def test_real_project_conversion_config_loads(self, real_config: LabConfig) -> None:
        assert isinstance(load_conversion_config(real_config), ConversionConfig)


class TestAuxiliaryConfigReaders:
    def test_upstream_versions_absent_returns_empty(self, tiny_config: LabConfig) -> None:
        assert load_upstream_versions(tiny_config) == {}

    def test_upstream_versions_are_read(self, tmp_path: Path) -> None:
        root = build_project(tmp_path / "p")
        write_json(root / "config" / "upstream-versions.json", {"attack": "19.1"})
        assert load_upstream_versions(load_config(root)) == {"attack": "19.1"}

    def test_read_config_json_reads_a_file(self, tiny_config: LabConfig) -> None:
        assert read_config_json(tiny_config, "telemetry-catalog.json")["schema_version"]

    @pytest.mark.parametrize("filename", ["../secret.json", "a/b.json", "a\\b.json"])
    def test_read_config_json_refuses_a_path(self, tiny_config: LabConfig, filename: str) -> None:
        with pytest.raises(ConfigError, match="invalid config filename"):
            read_config_json(tiny_config, filename)

    def test_read_config_json_refuses_a_missing_file(self, tiny_config: LabConfig) -> None:
        with pytest.raises(ConfigError, match="not found"):
            read_config_json(tiny_config, "absent.json")
