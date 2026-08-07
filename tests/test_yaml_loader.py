"""Tests for the hardened YAML loader.

Sigma rules are untrusted input, so the loader is expected to refuse whole
classes of construct rather than parse them defensively later. These tests pin
each refusal to a specific reason.
"""

from __future__ import annotations

import re
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
import yaml

from sigma_detection_engineering_lab.errors import PathSafetyError, YamlSafetyError
from sigma_detection_engineering_lab.yaml_loader import (
    ALLOWED_TAGS,
    DEFAULT_LIMITS,
    YamlLimits,
    allowed_tags,
    dump_safe,
    limits_from_mapping,
    load_documents,
    load_mapping_documents,
    load_mapping_documents_file,
    load_mapping_file,
    load_single_document,
    load_single_mapping,
    load_yaml_file,
    require_mapping,
)


class TestLoadDocuments:
    def test_loads_single_mapping(self) -> None:
        documents = load_documents("title: example\n")
        assert documents == [{"title": "example"}]

    def test_loads_multiple_documents_in_stream_order(self) -> None:
        documents = load_documents("a: 1\n---\nb: 2\n---\nc: 3\n")
        assert documents == [{"a": 1}, {"b": 2}, {"c": 3}]

    def test_empty_string_yields_no_documents(self) -> None:
        assert load_documents("") == []

    def test_comment_only_stream_yields_no_documents(self) -> None:
        assert load_documents("# nothing but a comment\n") == []

    def test_scalar_document_is_returned_as_scalar(self) -> None:
        assert load_documents("just-a-string\n") == ["just-a-string"]

    def test_sequence_document_is_returned_as_list(self) -> None:
        assert load_documents("- one\n- two\n") == [["one", "two"]]

    def test_nested_structures_are_preserved(self) -> None:
        text = "detection:\n  selection:\n    Image: 'x.exe'\n  condition: selection\n"
        assert load_documents(text) == [
            {"detection": {"selection": {"Image": "x.exe"}, "condition": "selection"}}
        ]

    def test_integers_and_booleans_keep_their_types(self) -> None:
        document = load_documents("count: 3\nenabled: true\nratio: 1.5\nmissing: null\n")[0]
        assert document == {"count": 3, "enabled": True, "ratio": 1.5, "missing": None}

    def test_unicode_scalars_round_trip(self) -> None:
        assert load_documents("title: 'caffè — synthetic'\n")[0]["title"] == "caffè — synthetic"

    def test_source_label_appears_in_error_messages(self) -> None:
        with pytest.raises(YamlSafetyError, match=re.escape("rules/demo.yml")):
            load_documents("a: [\n", source="rules/demo.yml")

    def test_invalid_yaml_raises_yaml_safety_error(self) -> None:
        with pytest.raises(YamlSafetyError, match="invalid YAML"):
            load_documents("key: [unclosed\n")

    def test_tab_indentation_is_rejected_as_invalid_yaml(self) -> None:
        with pytest.raises(YamlSafetyError):
            load_documents("root:\n\tchild: 1\n")


class TestForbiddenTags:
    @pytest.mark.parametrize(
        "text",
        [
            "!!python/object/apply:os.system ['echo hi']\n",
            "value: !!python/name:os.system\n",
            "value: !!python/object:collections.OrderedDict {}\n",
        ],
    )
    def test_python_tags_are_refused(self, text: str) -> None:
        with pytest.raises(YamlSafetyError):
            load_documents(text)

    def test_binary_tag_is_refused(self) -> None:
        with pytest.raises(YamlSafetyError, match="forbidden YAML tag"):
            load_documents("blob: !!binary aGVsbG8=\n")

    def test_custom_application_tag_is_refused(self) -> None:
        with pytest.raises(YamlSafetyError, match="forbidden YAML tag"):
            load_documents("value: !myapp/Thing {}\n")

    def test_set_tag_is_refused(self) -> None:
        with pytest.raises(YamlSafetyError, match="forbidden YAML tag"):
            load_documents("value: !!set\n  ? a\n  ? b\n")

    def test_pairs_tag_is_refused(self) -> None:
        with pytest.raises(YamlSafetyError, match="forbidden YAML tag"):
            load_documents("value: !!pairs\n  - a: 1\n")

    def test_error_message_names_the_offending_tag(self) -> None:
        with pytest.raises(YamlSafetyError) as excinfo:
            load_documents("blob: !!binary aGVsbG8=\n")
        assert "tag:yaml.org,2002:binary" in str(excinfo.value)

    def test_error_message_reports_a_position(self) -> None:
        with pytest.raises(YamlSafetyError, match=r"line \d+, column \d+"):
            load_documents("a: 1\nblob: !!binary aGVsbG8=\n")

    def test_allowlist_contains_only_plain_data_tags(self) -> None:
        assert all(tag.startswith("tag:yaml.org,2002:") for tag in ALLOWED_TAGS)

    def test_allowlist_excludes_python_tags(self) -> None:
        assert not any("python" in tag for tag in ALLOWED_TAGS)

    def test_allowed_tags_helper_returns_sorted_list(self) -> None:
        tags = allowed_tags()
        assert list(tags) == sorted(ALLOWED_TAGS)


class TestAliasHandling:
    def test_alias_is_refused_by_default(self) -> None:
        text = "base: &anchor\n  a: 1\nderived: *anchor\n"
        with pytest.raises(YamlSafetyError, match="alias count exceeds limit"):
            load_documents(text)

    def test_alias_error_explains_the_expansion_risk(self) -> None:
        text = "base: &anchor {a: 1}\nderived: *anchor\n"
        with pytest.raises(YamlSafetyError, match="expansion attacks"):
            load_documents(text)

    def test_billion_laughs_is_refused(self) -> None:
        text = (
            "a: &a ['x','x','x','x','x','x','x','x','x']\n"
            "b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
            "c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n"
            "d: [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
        )
        with pytest.raises(YamlSafetyError, match="alias"):
            load_documents(text)

    def test_alias_is_allowed_when_budget_is_raised(self) -> None:
        text = "base: &anchor\n  a: 1\nderived: *anchor\n"
        limits = YamlLimits(max_aliases=2)
        assert load_documents(text, limits=limits)[0]["derived"] == {"a": 1}

    def test_alias_budget_is_exact(self) -> None:
        text = "base: &anchor 1\nx: *anchor\ny: *anchor\n"
        with pytest.raises(YamlSafetyError):
            load_documents(text, limits=YamlLimits(max_aliases=1))

    def test_anchor_without_alias_is_permitted(self) -> None:
        assert load_documents("base: &anchor 1\n")[0] == {"base": 1}

    def test_merge_key_is_refused(self) -> None:
        text = "base: &anchor {a: 1}\nchild:\n  <<: *anchor\n  b: 2\n"
        with pytest.raises(YamlSafetyError):
            load_documents(text)


class TestDuplicateKeys:
    def test_duplicate_mapping_key_is_refused(self) -> None:
        with pytest.raises(YamlSafetyError, match="duplicate mapping key"):
            load_documents("title: one\ntitle: two\n")

    def test_duplicate_key_message_names_the_key(self) -> None:
        with pytest.raises(YamlSafetyError, match="'title'"):
            load_documents("title: one\ntitle: two\n")

    def test_duplicate_key_message_reports_the_line(self) -> None:
        with pytest.raises(YamlSafetyError, match="line 3"):
            load_documents("a: 1\ntitle: one\ntitle: two\n")

    def test_duplicate_key_in_nested_mapping_is_refused(self) -> None:
        with pytest.raises(YamlSafetyError, match="duplicate mapping key"):
            load_documents("detection:\n  selection: a\n  selection: b\n")

    def test_duplicate_key_rationale_is_explained(self) -> None:
        with pytest.raises(YamlSafetyError, match="changes detection logic"):
            load_documents("a: 1\na: 2\n")

    def test_same_key_in_different_mappings_is_fine(self) -> None:
        document = load_documents("one:\n  key: a\ntwo:\n  key: b\n")[0]
        assert document == {"one": {"key": "a"}, "two": {"key": "b"}}


class TestStructuralLimits:
    def test_depth_limit_is_enforced(self) -> None:
        text = (
            "".join(f"{'  ' * index}level{index}:\n" for index in range(12))
            + f"{'  ' * 12}value: 1\n"
        )
        with pytest.raises(YamlSafetyError, match="nesting depth exceeds limit"):
            load_documents(text, limits=YamlLimits(max_depth=6))

    def test_depth_within_limit_is_accepted(self) -> None:
        assert load_documents("a:\n  b:\n    c: 1\n", limits=YamlLimits(max_depth=12))

    def test_node_count_limit_is_enforced(self) -> None:
        text = "".join(f"key{index}: {index}\n" for index in range(50))
        with pytest.raises(YamlSafetyError, match="node count exceeds limit"):
            load_documents(text, limits=YamlLimits(max_nodes=10))

    def test_scalar_length_limit_is_enforced(self) -> None:
        text = f"value: '{'x' * 200}'\n"
        with pytest.raises(YamlSafetyError, match="scalar length"):
            load_documents(text, limits=YamlLimits(max_scalar_length=64))

    def test_scalar_at_exactly_the_limit_is_accepted(self) -> None:
        text = f"value: '{'x' * 64}'\n"
        assert load_documents(text, limits=YamlLimits(max_scalar_length=64))[0]["value"]

    def test_mapping_size_limit_is_enforced(self) -> None:
        text = "".join(f"key{index}: {index}\n" for index in range(20))
        with pytest.raises(YamlSafetyError, match="mapping size"):
            load_documents(text, limits=YamlLimits(max_mapping_size=8))

    def test_sequence_length_limit_is_enforced(self) -> None:
        text = "items:\n" + "".join(f"  - {index}\n" for index in range(20))
        with pytest.raises(YamlSafetyError, match="sequence length"):
            load_documents(text, limits=YamlLimits(max_sequence_length=8))

    def test_file_size_limit_is_enforced(self) -> None:
        text = f"value: '{'x' * 5000}'\n"
        with pytest.raises(YamlSafetyError, match="document size"):
            load_documents(text, limits=YamlLimits(max_file_bytes=1024))

    def test_file_size_limit_counts_utf8_bytes(self) -> None:
        # Each 'é' is two bytes, so 40 characters exceed a 50-byte budget.
        text = f"value: '{'é' * 40}'\n"
        with pytest.raises(YamlSafetyError, match="document size"):
            load_documents(text, limits=YamlLimits(max_file_bytes=50))

    def test_document_count_limit_is_enforced(self) -> None:
        text = "---\n".join(f"index: {number}\n" for number in range(10))
        with pytest.raises(YamlSafetyError, match="document count exceeds limit"):
            load_documents(text, limits=YamlLimits(max_documents=3))

    def test_nul_byte_is_refused(self) -> None:
        with pytest.raises(YamlSafetyError, match="NUL byte"):
            load_documents("title: ex\x00ample\n")

    def test_deeply_nested_sequences_hit_the_depth_limit(self) -> None:
        text = "value: " + "[" * 40 + "]" * 40 + "\n"
        with pytest.raises(YamlSafetyError, match="nesting depth"):
            load_documents(text, limits=YamlLimits(max_depth=8))


class TestDefaultLimits:
    def test_default_forbids_aliases(self) -> None:
        assert DEFAULT_LIMITS.max_aliases == 0

    def test_default_depth_is_bounded(self) -> None:
        assert 0 < DEFAULT_LIMITS.max_depth <= 256

    def test_default_node_budget_is_bounded(self) -> None:
        assert 0 < DEFAULT_LIMITS.max_nodes <= 200_000

    def test_default_document_budget_is_small(self) -> None:
        assert 0 < DEFAULT_LIMITS.max_documents <= 64

    def test_limits_are_frozen(self) -> None:
        with pytest.raises(FrozenInstanceError):
            DEFAULT_LIMITS.max_depth = 1  # type: ignore[misc]


class TestLoadSingleDocument:
    def test_returns_the_only_document(self) -> None:
        assert load_single_document("a: 1\n") == {"a": 1}

    def test_rejects_empty_stream(self) -> None:
        with pytest.raises(YamlSafetyError, match="expected exactly one YAML document"):
            load_single_document("")

    def test_rejects_multi_document_stream(self) -> None:
        with pytest.raises(YamlSafetyError, match="found 2"):
            load_single_document("a: 1\n---\nb: 2\n")

    def test_accepts_a_scalar_document(self) -> None:
        assert load_single_document("hello\n") == "hello"


class TestRequireMapping:
    def test_accepts_a_string_keyed_mapping(self) -> None:
        assert require_mapping({"a": 1}) == {"a": 1}

    def test_returns_a_copy(self) -> None:
        original = {"a": 1}
        result = require_mapping(original)
        result["b"] = 2
        assert "b" not in original

    @pytest.mark.parametrize("document", [[], "text", 42, None, 3.5, True])
    def test_rejects_non_mapping_roots(self, document: object) -> None:
        with pytest.raises(YamlSafetyError, match="must be a mapping"):
            require_mapping(document)

    def test_rejects_integer_keys(self) -> None:
        with pytest.raises(YamlSafetyError, match="must be strings"):
            require_mapping({1: "a"})

    def test_error_names_the_source_label(self) -> None:
        with pytest.raises(YamlSafetyError, match=re.escape("rules/x.yml")):
            require_mapping([], source="rules/x.yml")


class TestLoadSingleMapping:
    def test_loads_a_mapping(self) -> None:
        assert load_single_mapping("title: x\n") == {"title": "x"}

    def test_rejects_sequence_root(self) -> None:
        with pytest.raises(YamlSafetyError, match="must be a mapping"):
            load_single_mapping("- a\n- b\n")

    def test_rejects_non_string_root_keys(self) -> None:
        with pytest.raises(YamlSafetyError, match="must be strings"):
            load_single_mapping("1: a\n")


class TestLoadMappingDocuments:
    def test_loads_every_document(self) -> None:
        assert load_mapping_documents("a: 1\n---\nb: 2\n") == [{"a": 1}, {"b": 2}]

    def test_rejects_an_empty_stream(self) -> None:
        with pytest.raises(YamlSafetyError, match="contains no documents"):
            load_mapping_documents("")

    def test_rejects_a_non_mapping_document(self) -> None:
        with pytest.raises(YamlSafetyError, match="must be a mapping"):
            load_mapping_documents("a: 1\n---\n- item\n")

    def test_error_identifies_the_offending_document_index(self) -> None:
        with pytest.raises(YamlSafetyError, match=r"\[document 1\]"):
            load_mapping_documents("a: 1\n---\n- item\n")


class TestFileHelpers:
    def test_load_yaml_file_reads_all_documents(self, tmp_path: Path) -> None:
        path = tmp_path / "rule.yml"
        path.write_text("a: 1\n---\nb: 2\n", encoding="utf-8")
        assert load_yaml_file(path) == [{"a": 1}, {"b": 2}]

    def test_load_mapping_file_reads_one_mapping(self, tmp_path: Path) -> None:
        path = tmp_path / "rule.yml"
        path.write_text("title: x\n", encoding="utf-8")
        assert load_mapping_file(path) == {"title": "x"}

    def test_load_mapping_documents_file_reads_a_stream(self, tmp_path: Path) -> None:
        path = tmp_path / "correlation.yml"
        path.write_text("name: base\n---\ncorrelation: {}\n", encoding="utf-8")
        assert len(load_mapping_documents_file(path)) == 2

    def test_file_helper_uses_path_as_default_source_label(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.yml"
        path.write_text("a: 1\na: 2\n", encoding="utf-8")
        with pytest.raises(YamlSafetyError, match=re.escape("broken.yml")):
            load_mapping_file(path)

    def test_file_helper_honours_an_explicit_source_label(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.yml"
        path.write_text("a: 1\na: 2\n", encoding="utf-8")
        with pytest.raises(YamlSafetyError, match=re.escape("rules/label.yml")):
            load_mapping_file(path, source="rules/label.yml")

    def test_oversized_file_is_refused_before_parsing(self, tmp_path: Path) -> None:
        path = tmp_path / "big.yml"
        path.write_text(f"value: '{'x' * 4000}'\n", encoding="utf-8")
        with pytest.raises(PathSafetyError):
            load_yaml_file(path, limits=YamlLimits(max_file_bytes=1024))


class TestDumpSafe:
    def test_round_trips_plain_data(self) -> None:
        data = {"title": "x", "tags": ["a", "b"], "count": 2}
        assert load_single_document(dump_safe(data)) == data

    def test_output_has_no_python_tags(self) -> None:
        assert "!!python" not in dump_safe({"a": 1})

    def test_sort_keys_is_off_by_default(self) -> None:
        rendered = dump_safe({"b": 1, "a": 2})
        assert rendered.index("b:") < rendered.index("a:")

    def test_sort_keys_can_be_enabled(self) -> None:
        rendered = dump_safe({"b": 1, "a": 2}, sort_keys=True)
        assert rendered.index("a:") < rendered.index("b:")

    def test_unicode_is_not_escaped(self) -> None:
        assert "è" in dump_safe({"title": "caffè"})

    def test_block_style_is_used_for_nested_data(self) -> None:
        assert "\n" in dump_safe({"outer": {"inner": 1}}).strip()

    def test_dumping_an_unsupported_type_raises(self) -> None:
        with pytest.raises(yaml.YAMLError):
            dump_safe({"path": Path("x")})

    def test_dumped_output_reloads_under_default_limits(self) -> None:
        data = {"detection": {"selection": {"Image": "a.exe"}, "condition": "selection"}}
        assert load_single_mapping(dump_safe(data)) == data


class TestLimitsFromMapping:
    def test_maps_configuration_key_names(self) -> None:
        limits = limits_from_mapping(
            {
                "max_file_bytes": 2048,
                "max_yaml_depth": 10,
                "max_yaml_nodes": 100,
                "max_yaml_aliases": 3,
                "max_scalar_length": 64,
                "max_mapping_size": 16,
                "max_sequence_length": 8,
            }
        )
        assert (limits.max_file_bytes, limits.max_depth, limits.max_nodes) == (2048, 10, 100)
        assert (limits.max_aliases, limits.max_scalar_length) == (3, 64)
        assert (limits.max_mapping_size, limits.max_sequence_length) == (16, 8)

    def test_absent_keys_fall_back_to_defaults(self) -> None:
        limits = limits_from_mapping({})
        assert limits.max_depth == DEFAULT_LIMITS.max_depth
        assert limits.max_aliases == DEFAULT_LIMITS.max_aliases

    def test_unknown_keys_are_ignored(self) -> None:
        assert limits_from_mapping({"max_events_per_fixture": 5}).max_depth

    def test_result_is_usable_as_a_limit_object(self) -> None:
        limits = limits_from_mapping({"max_yaml_depth": 4})
        with pytest.raises(YamlSafetyError):
            load_documents("a:\n  b:\n    c:\n      d:\n        e: 1\n", limits=limits)
