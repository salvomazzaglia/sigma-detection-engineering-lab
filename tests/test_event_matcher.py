"""Tests for the deterministic event matcher.

The matcher documents an explicit answer wherever the Sigma specification leaves
room for backend interpretation. These tests pin those answers so a change in
semantics cannot pass unnoticed.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from conftest import make_event, make_rule
from sigma_detection_engineering_lab.errors import (
    MatcherError,
    RegexSafetyError,
    UnsupportedModifierError,
)
from sigma_detection_engineering_lab.event_matcher import (
    COMPARISON_MODIFIERS,
    DEFAULT_OPTIONS,
    MAX_QUANTIFIERS,
    MAX_REPEAT_BOUND,
    SUPPORTED_MODIFIERS,
    DetectionMatcher,
    MatchOptions,
    RuleMatcher,
    assert_safe_regex,
    build_rule_matcher,
    compile_regex,
    compile_selection,
    sigma_wildcard_to_regex,
)
from sigma_detection_engineering_lab.models import LogSource


def match(detection: dict[str, Any], fields: dict[str, Any], **event_kwargs: Any) -> bool:
    """Compile a detection and evaluate it against a single-event fixture."""
    matcher = DetectionMatcher(detection)
    return matcher.match(make_event(fields=fields, **event_kwargs))


def selection(**pairs: Any) -> dict[str, Any]:
    """Build a one-selection detection whose condition is that selection."""
    return {"selection": dict(pairs), "condition": "selection"}


class TestPlainComparison:
    def test_exact_value_matches(self) -> None:
        assert match(selection(Image="cmd.exe"), {"Image": "cmd.exe"}) is True

    def test_different_value_does_not_match(self) -> None:
        assert match(selection(Image="cmd.exe"), {"Image": "powershell.exe"}) is False

    def test_comparison_is_case_insensitive_by_default(self) -> None:
        assert match(selection(Image="CMD.EXE"), {"Image": "cmd.exe"}) is True

    def test_partial_value_does_not_match_without_a_modifier(self) -> None:
        assert match(selection(Image="cmd"), {"Image": "cmd.exe"}) is False

    def test_absent_field_does_not_match(self) -> None:
        assert match(selection(Image="cmd.exe"), {"CommandLine": "x"}) is False

    def test_integer_values_compare_numerically(self) -> None:
        assert match(selection(EventID=4624), {"EventID": 4624}) is True

    def test_integer_and_string_forms_are_interchangeable(self) -> None:
        assert match(selection(EventID=4624), {"EventID": "4624"}) is True

    def test_numeric_mismatch_does_not_match(self) -> None:
        assert match(selection(EventID=4624), {"EventID": 4625}) is False

    def test_boolean_renders_as_lowercase_text(self) -> None:
        assert match(selection(Elevated=True), {"Elevated": True}) is True

    def test_trailing_newline_does_not_satisfy_an_exact_match(self) -> None:
        assert match(selection(Image="cmd.exe"), {"Image": "cmd.exe\n"}) is False

    def test_field_lookup_is_case_insensitive(self) -> None:
        assert match(selection(image="cmd.exe"), {"Image": "cmd.exe"}) is True

    def test_top_level_host_alias_resolves(self) -> None:
        assert (
            match(selection(Computer="SYNTHETIC-HOST-01"), {"Image": "x"}, host="SYNTHETIC-HOST-01")
            is True
        )

    def test_top_level_user_alias_resolves(self) -> None:
        assert match(selection(User="synthetic-user"), {}, user="synthetic-user") is True

    def test_explicit_field_overrides_a_top_level_alias(self) -> None:
        assert (
            match(selection(Computer="OTHER-HOST"), {"Computer": "OTHER-HOST"}, host="SYNTH-1")
            is True
        )


class TestValueLists:
    def test_list_of_values_is_a_disjunction(self) -> None:
        detection = selection(Image=["cmd.exe", "powershell.exe"])
        assert match(detection, {"Image": "powershell.exe"}) is True

    def test_list_disjunction_fails_when_nothing_matches(self) -> None:
        detection = selection(Image=["cmd.exe", "powershell.exe"])
        assert match(detection, {"Image": "wscript.exe"}) is False

    def test_all_modifier_turns_a_list_into_a_conjunction(self) -> None:
        detection = {
            "selection": {"CommandLine|contains|all": ["-enc", "-nop"]},
            "condition": "selection",
        }
        assert match(detection, {"CommandLine": "pwsh -nop -enc AAA"}) is True

    def test_all_modifier_fails_when_one_value_is_absent(self) -> None:
        detection = {
            "selection": {"CommandLine|contains|all": ["-enc", "-nop"]},
            "condition": "selection",
        }
        assert match(detection, {"CommandLine": "pwsh -enc AAA"}) is False

    def test_multi_valued_event_field_matches_on_any_element(self) -> None:
        assert match(selection(Tag="beta"), {"Tag": ["alpha", "beta"]}) is True

    def test_multi_valued_event_field_fails_when_no_element_matches(self) -> None:
        assert match(selection(Tag="gamma"), {"Tag": ["alpha", "beta"]}) is False

    def test_all_modifier_against_a_multi_valued_field(self) -> None:
        detection = {"selection": {"Tag|all": ["alpha", "beta"]}, "condition": "selection"}
        assert match(detection, {"Tag": ["alpha", "beta", "gamma"]}) is True


class TestNullSemantics:
    def test_null_expected_matches_an_absent_field(self) -> None:
        assert match(selection(Image=None), {"CommandLine": "x"}) is True

    def test_null_expected_matches_a_present_null_field(self) -> None:
        assert match(selection(Image=None), {"Image": None}) is True

    def test_null_expected_does_not_match_a_populated_field(self) -> None:
        assert match(selection(Image=None), {"Image": "cmd.exe"}) is False

    def test_null_inside_a_list_permits_absence(self) -> None:
        assert match(selection(Image=["cmd.exe", None]), {"Other": 1}) is True

    def test_null_inside_a_list_still_matches_a_listed_value(self) -> None:
        assert match(selection(Image=["cmd.exe", None]), {"Image": "cmd.exe"}) is True


class TestContainsModifier:
    def test_substring_matches(self) -> None:
        detection = {"selection": {"CommandLine|contains": "-enc"}, "condition": "selection"}
        assert match(detection, {"CommandLine": "pwsh -enc AAA"}) is True

    def test_missing_substring_does_not_match(self) -> None:
        detection = {"selection": {"CommandLine|contains": "-dec"}, "condition": "selection"}
        assert match(detection, {"CommandLine": "pwsh -enc AAA"}) is False

    def test_contains_is_case_insensitive_by_default(self) -> None:
        detection = {"selection": {"CommandLine|contains": "-ENC"}, "condition": "selection"}
        assert match(detection, {"CommandLine": "pwsh -enc"}) is True

    def test_contains_matches_at_the_start(self) -> None:
        detection = {"selection": {"CommandLine|contains": "pwsh"}, "condition": "selection"}
        assert match(detection, {"CommandLine": "pwsh -enc"}) is True

    def test_contains_spans_a_newline_in_the_value(self) -> None:
        detection = {"selection": {"CommandLine|contains": "b"}, "condition": "selection"}
        assert match(detection, {"CommandLine": "a\nb"}) is True


class TestStartswithEndswith:
    def test_startswith_matches_a_prefix(self) -> None:
        detection = {"selection": {"Image|startswith": "C:\\Temp"}, "condition": "selection"}
        assert match(detection, {"Image": "C:\\Temp\\tool.exe"}) is True

    def test_startswith_rejects_a_middle_occurrence(self) -> None:
        detection = {"selection": {"Image|startswith": "Temp"}, "condition": "selection"}
        assert match(detection, {"Image": "C:\\Temp\\tool.exe"}) is False

    def test_endswith_matches_a_suffix(self) -> None:
        detection = {"selection": {"Image|endswith": "\\tool.exe"}, "condition": "selection"}
        assert match(detection, {"Image": "C:\\Temp\\tool.exe"}) is True

    def test_endswith_rejects_a_middle_occurrence(self) -> None:
        detection = {"selection": {"Image|endswith": "Temp"}, "condition": "selection"}
        assert match(detection, {"Image": "C:\\Temp\\tool.exe"}) is False

    def test_endswith_ignores_a_trailing_newline_claim(self) -> None:
        detection = {"selection": {"Image|endswith": ".exe"}, "condition": "selection"}
        assert match(detection, {"Image": "tool.exe\n"}) is False

    def test_startswith_is_case_insensitive(self) -> None:
        detection = {"selection": {"Image|startswith": "c:\\temp"}, "condition": "selection"}
        assert match(detection, {"Image": "C:\\Temp\\x.exe"}) is True


class TestCasedModifier:
    def test_cased_makes_comparison_case_sensitive(self) -> None:
        detection = {"selection": {"Image|cased": "CMD.EXE"}, "condition": "selection"}
        assert match(detection, {"Image": "cmd.exe"}) is False

    def test_cased_matches_an_exact_case_value(self) -> None:
        detection = {"selection": {"Image|cased": "cmd.exe"}, "condition": "selection"}
        assert match(detection, {"Image": "cmd.exe"}) is True

    def test_cased_combines_with_contains(self) -> None:
        detection = {
            "selection": {"CommandLine|contains|cased": "Enc"},
            "condition": "selection",
        }
        assert match(detection, {"CommandLine": "pwsh -enc"}) is False

    def test_cased_combines_with_regex(self) -> None:
        detection = {"selection": {"Image|re|cased": "^CMD"}, "condition": "selection"}
        assert match(detection, {"Image": "cmd.exe"}) is False


class TestWildcards:
    def test_star_matches_any_run(self) -> None:
        # In Sigma a literal backslash is written doubled, so the only wildcard
        # here is the '*'.
        detection = selection(Image="C:\\\\*\\\\tool.exe")
        assert match(detection, {"Image": "C:\\Temp\\tool.exe"}) is True

    def test_star_matches_an_empty_run(self) -> None:
        assert match(selection(Image="cmd*.exe"), {"Image": "cmd.exe"}) is True

    def test_question_mark_matches_exactly_one_character(self) -> None:
        assert match(selection(Image="cmd?.exe"), {"Image": "cmd1.exe"}) is True

    def test_question_mark_does_not_match_zero_characters(self) -> None:
        assert match(selection(Image="cmd?.exe"), {"Image": "cmd.exe"}) is False

    def test_escaped_star_is_a_literal(self) -> None:
        assert match(selection(Value="a\\*b"), {"Value": "a*b"}) is True

    def test_escaped_star_does_not_act_as_a_wildcard(self) -> None:
        assert match(selection(Value="a\\*b"), {"Value": "axb"}) is False

    def test_escaped_question_mark_is_a_literal(self) -> None:
        assert match(selection(Value="a\\?b"), {"Value": "a?b"}) is True

    def test_escaped_backslash_is_a_literal(self) -> None:
        assert match(selection(Value="a\\\\b"), {"Value": "a\\b"}) is True

    def test_regex_metacharacters_are_escaped(self) -> None:
        assert match(selection(Value="a.b"), {"Value": "axb"}) is False

    def test_bracket_characters_are_literal(self) -> None:
        assert match(selection(Value="[abc]"), {"Value": "[abc]"}) is True


class TestSigmaWildcardToRegex:
    def test_star_becomes_dot_star(self) -> None:
        assert sigma_wildcard_to_regex("a*b") == "a.*b"

    def test_question_becomes_dot(self) -> None:
        assert sigma_wildcard_to_regex("a?b") == "a.b"

    def test_escaped_star_is_escaped_literally(self) -> None:
        assert re.fullmatch(sigma_wildcard_to_regex("a\\*b"), "a*b")

    def test_escaped_question_is_escaped_literally(self) -> None:
        assert re.fullmatch(sigma_wildcard_to_regex("a\\?b"), "a?b")

    def test_escaped_backslash_is_escaped_literally(self) -> None:
        assert re.fullmatch(sigma_wildcard_to_regex("a\\\\b"), "a\\b")

    def test_lone_backslash_is_treated_as_a_literal(self) -> None:
        assert re.fullmatch(sigma_wildcard_to_regex("a\\b"), "a\\b")

    def test_regex_metacharacters_are_escaped(self) -> None:
        assert re.fullmatch(sigma_wildcard_to_regex("a.b"), "a.b")
        assert not re.fullmatch(sigma_wildcard_to_regex("a.b"), "axb")

    def test_empty_string_yields_empty_pattern(self) -> None:
        assert sigma_wildcard_to_regex("") == ""

    def test_result_is_a_compilable_pattern(self) -> None:
        assert re.compile(sigma_wildcard_to_regex("C:\\Windows\\*.exe"))


class TestRegexModifier:
    def test_unanchored_search(self) -> None:
        detection = {"selection": {"CommandLine|re": "enc"}, "condition": "selection"}
        assert match(detection, {"CommandLine": "pwsh -enc AAA"}) is True

    def test_anchored_pattern_is_honoured(self) -> None:
        detection = {"selection": {"CommandLine|re": "^pwsh"}, "condition": "selection"}
        assert match(detection, {"CommandLine": "run pwsh"}) is False

    def test_regex_is_case_insensitive_by_default(self) -> None:
        detection = {"selection": {"Image|re": "CMD"}, "condition": "selection"}
        assert match(detection, {"Image": "cmd.exe"}) is True

    def test_character_class_works(self) -> None:
        detection = {"selection": {"Image|re": "cmd[0-9]\\.exe"}, "condition": "selection"}
        assert match(detection, {"Image": "cmd7.exe"}) is True

    def test_invalid_pattern_is_refused(self) -> None:
        with pytest.raises(RegexSafetyError, match="invalid regular expression"):
            DetectionMatcher({"selection": {"Image|re": "("}, "condition": "selection"})

    def test_regex_list_is_a_disjunction(self) -> None:
        detection = {"selection": {"Image|re": ["^cmd", "^pwsh"]}, "condition": "selection"}
        assert match(detection, {"Image": "pwsh.exe"}) is True


class TestRegexSafety:
    def test_short_safe_pattern_is_accepted(self) -> None:
        assert assert_safe_regex("abc.*def") is None

    def test_oversized_pattern_is_refused(self) -> None:
        with pytest.raises(RegexSafetyError, match="exceeds limit"):
            assert_safe_regex("a" * 300, max_length=256)

    def test_length_limit_is_configurable(self) -> None:
        assert assert_safe_regex("a" * 300, max_length=1000) is None

    def test_too_many_quantifiers_are_refused(self) -> None:
        with pytest.raises(RegexSafetyError, match="quantifiers exceed"):
            assert_safe_regex("a*" * (MAX_QUANTIFIERS + 2))

    def test_nested_quantifier_is_refused(self) -> None:
        with pytest.raises(RegexSafetyError, match="nested quantifier"):
            assert_safe_regex("(a+)+")

    def test_nested_star_quantifier_is_refused(self) -> None:
        with pytest.raises(RegexSafetyError, match="nested quantifier"):
            assert_safe_regex("(a*)*")

    def test_nested_quantifier_with_repeat_bound_is_refused(self) -> None:
        with pytest.raises(RegexSafetyError, match="nested quantifier"):
            assert_safe_regex("(a+){2}")

    def test_unquantified_group_is_accepted(self) -> None:
        assert assert_safe_regex("(abc)def") is None

    def test_quantified_group_without_inner_quantifier_is_accepted(self) -> None:
        assert assert_safe_regex("(abc)+") is None

    def test_large_repetition_bound_is_refused(self) -> None:
        with pytest.raises(RegexSafetyError, match="repetition bound"):
            assert_safe_regex(f"a{{{MAX_REPEAT_BOUND + 1}}}")

    def test_reasonable_repetition_bound_is_accepted(self) -> None:
        assert assert_safe_regex("a{5,10}") is None

    def test_backreference_is_refused(self) -> None:
        with pytest.raises(RegexSafetyError, match="backreferences"):
            assert_safe_regex("(a)\\1")

    def test_escaped_quantifier_does_not_count(self) -> None:
        assert assert_safe_regex("\\*" * 30) is None

    def test_quantifier_inside_a_character_class_does_not_count(self) -> None:
        assert assert_safe_regex("[*+]" * 20) is None

    def test_catastrophic_check_can_be_disabled(self) -> None:
        assert assert_safe_regex("(a+)+", reject_catastrophic=False) is None

    def test_subject_label_appears_in_the_message(self) -> None:
        with pytest.raises(RegexSafetyError, match="SDEL-TST-001"):
            assert_safe_regex("(a+)+", subject="SDEL-TST-001")

    def test_compile_regex_returns_a_compiled_pattern(self) -> None:
        assert compile_regex("abc", case_sensitive=True).pattern == "abc"

    def test_compile_regex_applies_ignorecase_when_not_cased(self) -> None:
        assert compile_regex("abc", case_sensitive=False).flags & re.IGNORECASE

    def test_compile_regex_omits_ignorecase_when_cased(self) -> None:
        assert not compile_regex("abc", case_sensitive=True).flags & re.IGNORECASE

    def test_compile_regex_refuses_an_unsafe_pattern(self) -> None:
        with pytest.raises(RegexSafetyError):
            compile_regex("(a+)+", case_sensitive=False)

    def test_compile_regex_honours_option_length_limit(self) -> None:
        options = MatchOptions(max_regex_length=4)
        with pytest.raises(RegexSafetyError):
            compile_regex("abcdefgh", case_sensitive=False, options=options)


class TestCidrModifier:
    def test_address_inside_the_network_matches(self) -> None:
        detection = {"selection": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "selection"}
        assert match(detection, {"DestinationIp": "10.1.2.3"}) is True

    def test_address_outside_the_network_does_not_match(self) -> None:
        detection = {"selection": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "selection"}
        assert match(detection, {"DestinationIp": "192.168.1.1"}) is False

    def test_multiple_networks_are_a_disjunction(self) -> None:
        detection = {
            "selection": {"DestinationIp|cidr": ["10.0.0.0/8", "192.168.0.0/16"]},
            "condition": "selection",
        }
        assert match(detection, {"DestinationIp": "192.168.5.5"}) is True

    def test_ipv6_networks_are_supported(self) -> None:
        detection = {"selection": {"SourceIp|cidr": "fd00::/8"}, "condition": "selection"}
        assert match(detection, {"SourceIp": "fd00::1"}) is True

    def test_single_host_network_is_accepted(self) -> None:
        detection = {"selection": {"SourceIp|cidr": "10.0.0.1/32"}, "condition": "selection"}
        assert match(detection, {"SourceIp": "10.0.0.1"}) is True

    def test_non_address_value_does_not_match(self) -> None:
        detection = {"selection": {"SourceIp|cidr": "10.0.0.0/8"}, "condition": "selection"}
        assert match(detection, {"SourceIp": "not-an-address"}) is False

    def test_whitespace_around_the_address_is_tolerated(self) -> None:
        detection = {"selection": {"SourceIp|cidr": "10.0.0.0/8"}, "condition": "selection"}
        assert match(detection, {"SourceIp": " 10.0.0.9 "}) is True

    def test_invalid_network_is_refused_at_compile_time(self) -> None:
        with pytest.raises(MatcherError, match="invalid CIDR"):
            DetectionMatcher(
                {"selection": {"SourceIp|cidr": "not-a-network"}, "condition": "selection"}
            )

    def test_host_bits_are_tolerated_because_strict_is_off(self) -> None:
        detection = {"selection": {"SourceIp|cidr": "10.1.2.3/8"}, "condition": "selection"}
        assert match(detection, {"SourceIp": "10.9.9.9"}) is True

    def test_all_modifier_requires_membership_in_every_network(self) -> None:
        detection = {
            "selection": {"SourceIp|cidr|all": ["10.0.0.0/8", "192.168.0.0/16"]},
            "condition": "selection",
        }
        assert match(detection, {"SourceIp": "10.0.0.1"}) is False


class TestExistsModifier:
    def test_exists_true_matches_a_present_field(self) -> None:
        detection = {"selection": {"Image|exists": True}, "condition": "selection"}
        assert match(detection, {"Image": "cmd.exe"}) is True

    def test_exists_true_does_not_match_an_absent_field(self) -> None:
        detection = {"selection": {"Image|exists": True}, "condition": "selection"}
        assert match(detection, {"Other": 1}) is False

    def test_exists_false_matches_an_absent_field(self) -> None:
        detection = {"selection": {"Image|exists": False}, "condition": "selection"}
        assert match(detection, {"Other": 1}) is True

    def test_exists_true_matches_a_field_holding_null(self) -> None:
        detection = {"selection": {"Image|exists": True}, "condition": "selection"}
        assert match(detection, {"Image": None}) is True

    def test_exists_requires_a_boolean_value(self) -> None:
        with pytest.raises(MatcherError, match="requires a boolean"):
            DetectionMatcher({"selection": {"Image|exists": "yes"}, "condition": "selection"})


class TestKeywords:
    def test_keyword_searches_every_field_value(self) -> None:
        detection = {"keywords": ["mimikatz"], "condition": "keywords"}
        assert match(detection, {"CommandLine": "run mimikatz now"}) is True

    def test_keyword_that_is_absent_does_not_match(self) -> None:
        detection = {"keywords": ["mimikatz"], "condition": "keywords"}
        assert match(detection, {"CommandLine": "run notepad"}) is False

    def test_keyword_list_is_a_disjunction(self) -> None:
        detection = {"keywords": ["alpha", "beta"], "condition": "keywords"}
        assert match(detection, {"CommandLine": "beta"}) is True

    def test_keyword_is_case_insensitive(self) -> None:
        detection = {"keywords": ["MIMIKATZ"], "condition": "keywords"}
        assert match(detection, {"CommandLine": "mimikatz"}) is True

    def test_keyword_searches_the_host_attribute(self) -> None:
        detection = {"keywords": ["SYNTHETIC-HOST-01"], "condition": "keywords"}
        assert match(detection, {"Other": 1}, host="SYNTHETIC-HOST-01") is True

    def test_keyword_searches_the_user_attribute(self) -> None:
        detection = {"keywords": ["synthetic-user"], "condition": "keywords"}
        assert match(detection, {"Other": 1}, user="synthetic-user") is True

    def test_keyword_searches_list_valued_fields(self) -> None:
        detection = {"keywords": ["beta"], "condition": "keywords"}
        assert match(detection, {"Tags": ["alpha", "beta"]}) is True

    def test_keyword_supports_wildcards(self) -> None:
        detection = {"keywords": ["mimi*"], "condition": "keywords"}
        assert match(detection, {"CommandLine": "mimikatz"}) is True


class TestUnsupportedModifiers:
    @pytest.mark.parametrize(
        "modifier",
        ["base64", "base64offset", "utf16", "wide", "gt", "lt", "gte", "lte", "expand"],
    )
    def test_unsupported_modifier_is_refused(self, modifier: str) -> None:
        detection = {"selection": {f"Field|{modifier}": "x"}, "condition": "selection"}
        with pytest.raises(UnsupportedModifierError):
            DetectionMatcher(detection)

    def test_error_lists_the_supported_modifiers(self) -> None:
        detection = {"selection": {"Field|base64": "x"}, "condition": "selection"}
        with pytest.raises(UnsupportedModifierError, match="contains"):
            DetectionMatcher(detection)

    def test_mutually_exclusive_comparison_modifiers_are_refused(self) -> None:
        detection = {"selection": {"Field|contains|startswith": "x"}, "condition": "selection"}
        with pytest.raises(UnsupportedModifierError, match="mutually exclusive"):
            DetectionMatcher(detection)

    def test_supported_set_matches_the_documented_subset(self) -> None:
        assert (
            frozenset(
                {"contains", "startswith", "endswith", "re", "cidr", "exists", "all", "cased"}
            )
            == SUPPORTED_MODIFIERS
        )

    def test_comparison_modifiers_are_a_subset_of_supported(self) -> None:
        assert COMPARISON_MODIFIERS <= SUPPORTED_MODIFIERS

    def test_all_and_cased_are_not_comparison_modifiers(self) -> None:
        assert not {"all", "cased"} & COMPARISON_MODIFIERS

    def test_options_can_narrow_the_supported_set(self) -> None:
        options = MatchOptions(supported_modifiers=frozenset({"contains"}))
        detection = {"selection": {"Field|re": "x"}, "condition": "selection"}
        with pytest.raises(UnsupportedModifierError):
            DetectionMatcher(detection, options=options)


class TestSelectionStructure:
    def test_selection_list_is_a_disjunction_of_branches(self) -> None:
        detection = {
            "selection": [{"Image": "cmd.exe"}, {"Image": "pwsh.exe"}],
            "condition": "selection",
        }
        assert match(detection, {"Image": "pwsh.exe"}) is True

    def test_selection_mapping_is_a_conjunction_of_fields(self) -> None:
        detection = selection(Image="cmd.exe", User="synthetic-user")
        assert match(detection, {"Image": "cmd.exe"}) is False

    def test_selection_mapping_matches_when_every_field_holds(self) -> None:
        detection = selection(Image="cmd.exe", User="synthetic-user")
        assert match(detection, {"Image": "cmd.exe", "User": "synthetic-user"}) is True

    def test_empty_selection_list_is_refused(self) -> None:
        with pytest.raises(MatcherError, match="must not be empty"):
            compile_selection("selection", [])

    def test_scalar_selection_is_refused(self) -> None:
        with pytest.raises(MatcherError, match="must be a mapping or a list"):
            compile_selection("selection", 42)

    def test_selection_entry_of_wrong_type_is_refused(self) -> None:
        with pytest.raises(MatcherError, match="mapping or a keyword scalar"):
            compile_selection("selection", [None])

    def test_empty_field_name_is_refused(self) -> None:
        with pytest.raises(MatcherError, match="empty field name"):
            compile_selection("selection", {"|contains": "x"})

    def test_compiled_selection_records_its_name(self) -> None:
        assert compile_selection("selection", {"a": 1}).name == "selection"

    def test_compiled_selection_records_its_branches(self) -> None:
        compiled = compile_selection("selection", [{"a": 1}, {"b": 2}])
        assert len(compiled.branches) == 2


class TestDetectionMatcherStructure:
    def test_missing_condition_is_refused(self) -> None:
        with pytest.raises(MatcherError, match="missing 'condition'"):
            DetectionMatcher({"selection": {"a": 1}})

    def test_detection_without_selections_is_refused(self) -> None:
        with pytest.raises(MatcherError, match="defines no selections"):
            DetectionMatcher({"condition": "selection"})

    def test_non_mapping_detection_is_refused(self) -> None:
        with pytest.raises(MatcherError, match="must be a mapping"):
            DetectionMatcher([])  # type: ignore[arg-type]

    def test_timeframe_is_refused_with_a_correlation_hint(self) -> None:
        detection = {"selection": {"a": 1}, "timeframe": "5m", "condition": "selection"}
        with pytest.raises(MatcherError, match="correlation rule"):
            DetectionMatcher(detection)

    def test_condition_referencing_an_undefined_selection_is_refused(self) -> None:
        with pytest.raises(MatcherError, match="undefined selection"):
            DetectionMatcher({"selection": {"a": 1}, "condition": "missing"})

    def test_selection_names_are_recorded_in_order(self) -> None:
        matcher = DetectionMatcher(
            {"sel_a": {"a": 1}, "sel_b": {"b": 2}, "condition": "1 of sel_*"}
        )
        assert matcher.selection_names == ("sel_a", "sel_b")

    def test_source_label_appears_in_errors(self) -> None:
        with pytest.raises(MatcherError, match="SDEL-TST-001"):
            DetectionMatcher({"condition": "x"}, source="SDEL-TST-001")


class TestConditionEvaluation:
    def test_filter_is_subtracted(self) -> None:
        detection = {
            "selection": {"Image|endswith": ".exe"},
            "filter": {"Image|contains": "approved"},
            "condition": "selection and not filter",
        }
        assert match(detection, {"Image": "approved.exe"}) is False
        assert match(detection, {"Image": "other.exe"}) is True

    def test_one_of_prefix_pattern(self) -> None:
        detection = {
            "selection_a": {"Image": "a.exe"},
            "selection_b": {"Image": "b.exe"},
            "condition": "1 of selection_*",
        }
        assert match(detection, {"Image": "b.exe"}) is True

    def test_all_of_prefix_pattern(self) -> None:
        detection = {
            "selection_a": {"Image": "a.exe"},
            "selection_b": {"User": "u"},
            "condition": "all of selection_*",
        }
        assert match(detection, {"Image": "a.exe", "User": "u"}) is True

    def test_all_of_them_covers_every_selection(self) -> None:
        detection = {"a": {"X": 1}, "b": {"Y": 2}, "condition": "all of them"}
        assert match(detection, {"X": 1}) is False


class TestMatchResult:
    def test_result_reports_the_rendered_condition(self) -> None:
        matcher = DetectionMatcher(selection(Image="cmd.exe"))
        assert matcher.evaluate(make_event(fields={"Image": "cmd.exe"})).condition == "selection"

    def test_result_records_per_selection_outcomes(self) -> None:
        detection = {
            "selection": {"Image": "cmd.exe"},
            "filter": {"User": "admin"},
            "condition": "selection and not filter",
        }
        result = DetectionMatcher(detection).evaluate(make_event(fields={"Image": "cmd.exe"}))
        assert result.selection_results == {"selection": True, "filter": False}

    def test_explanation_mentions_each_selection(self) -> None:
        result = DetectionMatcher(selection(Image="cmd.exe")).evaluate(
            make_event(fields={"Image": "cmd.exe"})
        )
        assert any("selection selection" in line for line in result.explanation)

    def test_explanation_ends_with_the_condition_verdict(self) -> None:
        result = DetectionMatcher(selection(Image="cmd.exe")).evaluate(
            make_event(fields={"Image": "cmd.exe"})
        )
        assert result.explanation[-1].startswith("condition ")

    def test_to_dict_is_json_friendly(self) -> None:
        result = DetectionMatcher(selection(Image="x")).evaluate(make_event(fields={"Image": "x"}))
        payload = result.to_dict()
        assert set(payload) == {"matched", "condition", "selection_results", "explanation"}
        assert isinstance(payload["explanation"], list)

    def test_selection_referenced_twice_is_evaluated_once(self) -> None:
        detection = {"selection": {"Image": "cmd.exe"}, "condition": "selection and selection"}
        result = DetectionMatcher(detection).evaluate(make_event(fields={"Image": "cmd.exe"}))
        assert len(result.selection_results) == 1

    def test_describe_lists_the_condition_first(self) -> None:
        lines = DetectionMatcher(selection(Image="cmd.exe")).describe()
        assert lines[0] == "condition: selection"

    def test_describe_lists_each_field_expression(self) -> None:
        lines = DetectionMatcher(selection(Image="cmd.exe")).describe()
        assert any("Image" in line for line in lines[1:])

    def test_describe_indexes_multi_branch_selections(self) -> None:
        detection = {
            "selection": [{"Image": "a.exe"}, {"Image": "b.exe"}],
            "condition": "selection",
        }
        assert any("selection[0]" in line for line in DetectionMatcher(detection).describe())

    def test_describe_renders_keyword_expressions(self) -> None:
        lines = DetectionMatcher({"keywords": ["mimikatz"], "condition": "keywords"}).describe()
        assert any("keyword(" in line for line in lines)


class TestRuleMatcher:
    def test_logsource_match_allows_evaluation(self) -> None:
        matcher = RuleMatcher(selection(Image="cmd.exe"), category="process_creation")
        assert matcher.match(make_event(fields={"Image": "cmd.exe"})) is True

    def test_logsource_mismatch_short_circuits(self) -> None:
        matcher = RuleMatcher(selection(Image="cmd.exe"), category="network_connection")
        assert matcher.match(make_event(fields={"Image": "cmd.exe"})) is False

    def test_logsource_mismatch_is_explained(self) -> None:
        matcher = RuleMatcher(selection(Image="cmd.exe"), category="network_connection")
        result = matcher.evaluate(make_event(fields={"Image": "cmd.exe"}))
        assert "logsource mismatch" in result.explanation[0]

    def test_logsource_mismatch_yields_no_selection_results(self) -> None:
        matcher = RuleMatcher(selection(Image="cmd.exe"), product="linux")
        assert matcher.evaluate(make_event(fields={"Image": "cmd.exe"})).selection_results == {}

    def test_unspecified_selector_component_matches_anything(self) -> None:
        matcher = RuleMatcher(selection(Image="cmd.exe"))
        assert matcher.match(make_event(fields={"Image": "cmd.exe"})) is True

    def test_logsource_comparison_is_case_insensitive(self) -> None:
        matcher = RuleMatcher(selection(Image="cmd.exe"), product="WINDOWS")
        assert matcher.match(make_event(fields={"Image": "cmd.exe"})) is True

    def test_service_selector_requires_a_service_on_the_event(self) -> None:
        matcher = RuleMatcher(selection(Image="cmd.exe"), service="security")
        assert matcher.match(make_event(fields={"Image": "cmd.exe"})) is False

    def test_logsource_enforcement_can_be_disabled(self) -> None:
        matcher = RuleMatcher(selection(Image="cmd.exe"), category="other", enforce_logsource=False)
        assert matcher.match(make_event(fields={"Image": "cmd.exe"})) is True

    def test_build_rule_matcher_uses_the_rule_logsource(self) -> None:
        rule = make_rule(
            detection=selection(Image="cmd.exe"),
            logsource=LogSource(category="process_creation", product="windows"),
        )
        matcher = build_rule_matcher(rule)
        assert matcher.category == "process_creation" and matcher.product == "windows"

    def test_build_rule_matcher_evaluates_the_rule_detection(self) -> None:
        rule = make_rule(detection=selection(Image="cmd.exe"))
        assert build_rule_matcher(rule).match(make_event(fields={"Image": "cmd.exe"})) is True

    def test_build_rule_matcher_can_ignore_logsource(self) -> None:
        rule = make_rule(
            detection=selection(Image="cmd.exe"),
            logsource=LogSource(category="dns_query", product="linux"),
        )
        matcher = build_rule_matcher(rule, enforce_logsource=False)
        assert matcher.match(make_event(fields={"Image": "cmd.exe"})) is True


class TestMatchOptions:
    def test_defaults_are_case_insensitive(self) -> None:
        assert DEFAULT_OPTIONS.default_case_sensitive is False

    def test_defaults_reject_catastrophic_patterns(self) -> None:
        assert DEFAULT_OPTIONS.reject_catastrophic_patterns is True

    def test_default_regex_length_is_bounded(self) -> None:
        assert 0 < DEFAULT_OPTIONS.max_regex_length <= 4096

    def test_from_profile_without_argument_uses_the_built_in_default(self) -> None:
        assert MatchOptions.from_profile().max_regex_length == 256

    def test_from_profile_copies_profile_values(self) -> None:
        from sigma_detection_engineering_lab.config import DEFAULT_EVALUATOR_PROFILE

        options = MatchOptions.from_profile(DEFAULT_EVALUATOR_PROFILE)
        assert options.supported_modifiers == DEFAULT_EVALUATOR_PROFILE.supported_modifiers

    def test_case_sensitive_default_can_be_enabled(self) -> None:
        options = MatchOptions(default_case_sensitive=True)
        matcher = DetectionMatcher(selection(Image="CMD.EXE"), options=options)
        assert matcher.match(make_event(fields={"Image": "cmd.exe"})) is False
