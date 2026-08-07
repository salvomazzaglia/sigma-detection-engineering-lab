"""Tests for the Sigma condition tokeniser, parser, and AST.

The parser implements a documented fragment of the grammar. Constructs outside
it must be refused by name rather than approximated, so most of these tests
assert on the refusal as much as on the parse.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from sigma_detection_engineering_lab.condition_model import (
    AndNode,
    ConditionNode,
    NotNode,
    OrNode,
    QuantifiedSelection,
    Quantifier,
    SelectionRef,
    build_and,
    build_or,
    describe,
)
from sigma_detection_engineering_lab.condition_parser import (
    AGGREGATION_KEYWORDS,
    MAX_CONDITION_LENGTH,
    MAX_PAREN_DEPTH,
    TokenType,
    is_supported_condition,
    parse_condition,
    tokenize,
)
from sigma_detection_engineering_lab.errors import (
    ConditionSyntaxError,
    UnsupportedConditionError,
)


def evaluate(condition: str, truths: dict[str, bool]) -> bool:
    """Parse and evaluate a condition against a selection truth table."""
    node = parse_condition(condition)
    return node.evaluate(lambda name: truths[name], tuple(truths))


class TestTokenize:
    def test_single_identifier(self) -> None:
        tokens = tokenize("selection")
        assert [token.type for token in tokens] == [TokenType.IDENT, TokenType.EOF]

    def test_identifier_text_is_preserved(self) -> None:
        assert tokenize("selection_main")[0].text == "selection_main"

    def test_keywords_are_recognised(self) -> None:
        types = [token.type for token in tokenize("a and b or not c")]
        assert TokenType.AND in types and TokenType.OR in types and TokenType.NOT in types

    def test_keywords_are_case_insensitive(self) -> None:
        assert [token.type for token in tokenize("a AND b")][1] is TokenType.AND

    def test_parentheses_produce_tokens(self) -> None:
        types = [token.type for token in tokenize("(a)")]
        assert types[0] is TokenType.LPAREN and types[2] is TokenType.RPAREN

    def test_positions_are_recorded(self) -> None:
        tokens = tokenize("a and b")
        assert [token.position for token in tokens[:3]] == [0, 2, 6]

    def test_whitespace_is_skipped(self) -> None:
        assert len(tokenize("  a   and   b  ")) == 4

    def test_one_is_a_quantifier_before_of(self) -> None:
        assert tokenize("1 of them")[0].type is TokenType.ONE

    def test_them_token_is_recognised(self) -> None:
        assert tokenize("1 of them")[2].type is TokenType.THEM

    def test_all_token_is_recognised(self) -> None:
        assert tokenize("all of them")[0].type is TokenType.ALL

    def test_trailing_star_stays_in_the_identifier(self) -> None:
        assert tokenize("1 of selection_*")[2].text == "selection_*"

    def test_dotted_identifier_is_one_token(self) -> None:
        assert tokenize("sel.one")[0].text == "sel.one"

    def test_hyphenated_identifier_is_one_token(self) -> None:
        assert tokenize("sel-one")[0].text == "sel-one"

    def test_aggregation_pipe_is_refused(self) -> None:
        with pytest.raises(UnsupportedConditionError, match="aggregation pipe"):
            tokenize("selection | count() > 5")

    @pytest.mark.parametrize("operator", ["<", ">", "=", "!"])
    def test_comparison_operators_are_refused(self, operator: str) -> None:
        with pytest.raises(UnsupportedConditionError, match="comparison operator"):
            tokenize(f"selection {operator} 5")

    @pytest.mark.parametrize("keyword", sorted(AGGREGATION_KEYWORDS - {"near"}))
    def test_aggregation_functions_are_refused(self, keyword: str) -> None:
        with pytest.raises(UnsupportedConditionError, match="aggregation function"):
            tokenize(f"selection and {keyword}")

    def test_near_is_refused_with_a_correlation_hint(self) -> None:
        with pytest.raises(UnsupportedConditionError, match="temporal"):
            tokenize("a near b")

    def test_unexpected_character_is_refused(self) -> None:
        with pytest.raises(ConditionSyntaxError, match="unexpected character"):
            tokenize("selection @ other")

    def test_oversized_condition_is_refused(self) -> None:
        with pytest.raises(ConditionSyntaxError, match="exceeds limit"):
            tokenize("a" * (MAX_CONDITION_LENGTH + 1))

    def test_token_count_limit_is_enforced(self) -> None:
        with pytest.raises(ConditionSyntaxError, match="token count"):
            tokenize(" or ".join(["a"] * 300))

    def test_stream_always_ends_with_eof(self) -> None:
        assert tokenize("a")[-1].type is TokenType.EOF

    def test_empty_text_yields_only_eof(self) -> None:
        assert [token.type for token in tokenize("")] == [TokenType.EOF]


class TestParseBasics:
    def test_single_selection(self) -> None:
        assert parse_condition("selection") == SelectionRef("selection")

    def test_conjunction(self) -> None:
        node = parse_condition("a and b")
        assert isinstance(node, AndNode) and len(node.operands) == 2

    def test_disjunction(self) -> None:
        node = parse_condition("a or b")
        assert isinstance(node, OrNode) and len(node.operands) == 2

    def test_negation(self) -> None:
        node = parse_condition("not a")
        assert isinstance(node, NotNode) and node.operand == SelectionRef("a")

    def test_chained_and_is_flattened_into_one_node(self) -> None:
        node = parse_condition("a and b and c")
        assert isinstance(node, AndNode) and len(node.operands) == 3

    def test_chained_or_is_flattened_into_one_node(self) -> None:
        node = parse_condition("a or b or c")
        assert isinstance(node, OrNode) and len(node.operands) == 3

    def test_and_binds_tighter_than_or(self) -> None:
        node = parse_condition("a or b and c")
        assert isinstance(node, OrNode)
        assert isinstance(node.operands[1], AndNode)

    def test_not_binds_tighter_than_and(self) -> None:
        node = parse_condition("not a and b")
        assert isinstance(node, AndNode)
        assert isinstance(node.operands[0], NotNode)

    def test_parentheses_override_precedence(self) -> None:
        node = parse_condition("(a or b) and c")
        assert isinstance(node, AndNode)
        assert isinstance(node.operands[0], OrNode)

    def test_double_negation_nests(self) -> None:
        node = parse_condition("not not a")
        assert isinstance(node, NotNode) and isinstance(node.operand, NotNode)

    def test_not_applies_to_a_parenthesised_group(self) -> None:
        node = parse_condition("not (a or b)")
        assert isinstance(node, NotNode) and isinstance(node.operand, OrNode)

    def test_surrounding_whitespace_is_ignored(self) -> None:
        assert parse_condition("   selection   ") == SelectionRef("selection")

    def test_nested_parentheses_parse(self) -> None:
        assert parse_condition("((a and b) or (c and d))")

    def test_redundant_parentheses_collapse(self) -> None:
        assert parse_condition("((a))") == SelectionRef("a")


class TestParseQuantifiers:
    def test_one_of_them(self) -> None:
        node = parse_condition("1 of them")
        assert isinstance(node, QuantifiedSelection)
        assert node.quantifier is Quantifier.ONE and node.is_them

    def test_all_of_them(self) -> None:
        node = parse_condition("all of them")
        assert isinstance(node, QuantifiedSelection)
        assert node.quantifier is Quantifier.ALL and node.is_them

    def test_one_of_prefix_pattern(self) -> None:
        node = parse_condition("1 of selection_*")
        assert isinstance(node, QuantifiedSelection) and node.pattern == "selection_*"

    def test_all_of_prefix_pattern(self) -> None:
        node = parse_condition("all of filter_*")
        assert isinstance(node, QuantifiedSelection) and node.pattern == "filter_*"

    def test_quantifier_combines_with_and(self) -> None:
        node = parse_condition("1 of selection_* and not 1 of filter_*")
        assert isinstance(node, AndNode)

    def test_all_alone_is_a_selection_name(self) -> None:
        assert parse_condition("all") == SelectionRef("all")

    def test_one_without_of_is_a_syntax_error(self) -> None:
        # A bare digit is only a quantifier when 'of' follows, so this fails in
        # the tokeniser rather than the parser.
        with pytest.raises(ConditionSyntaxError, match="unexpected character"):
            parse_condition("1 them")

    def test_of_without_a_target_is_a_syntax_error(self) -> None:
        with pytest.raises(ConditionSyntaxError, match="expected a selection pattern"):
            parse_condition("1 of")

    def test_them_outside_a_quantifier_is_a_syntax_error(self) -> None:
        with pytest.raises(ConditionSyntaxError, match="must follow"):
            parse_condition("them")

    def test_bare_wildcard_selection_is_refused(self) -> None:
        with pytest.raises(UnsupportedConditionError, match="bare wildcard"):
            parse_condition("selection_*")

    def test_bare_wildcard_error_suggests_the_quantified_form(self) -> None:
        with pytest.raises(UnsupportedConditionError, match=r"1 of <prefix>\*"):
            parse_condition("selection_*")

    def test_interior_wildcard_is_refused(self) -> None:
        # The identifier lexer only admits a trailing '*', so the remainder of an
        # interior-wildcard pattern is left dangling and rejected.
        with pytest.raises(ConditionSyntaxError, match="unexpected"):
            parse_condition("1 of sel*ion")

    def test_exact_name_after_of_is_accepted(self) -> None:
        node = parse_condition("all of selection")
        assert isinstance(node, QuantifiedSelection) and node.pattern == "selection"


class TestParseErrors:
    def test_none_is_refused(self) -> None:
        with pytest.raises(ConditionSyntaxError, match="condition is required"):
            parse_condition(None)

    def test_empty_string_is_refused(self) -> None:
        with pytest.raises(ConditionSyntaxError, match="condition is empty"):
            parse_condition("")

    def test_whitespace_only_is_refused(self) -> None:
        with pytest.raises(ConditionSyntaxError, match="condition is empty"):
            parse_condition("   ")

    def test_empty_list_is_refused(self) -> None:
        with pytest.raises(ConditionSyntaxError, match="condition list is empty"):
            parse_condition([])

    @pytest.mark.parametrize("condition", [42, 3.5, {"a": 1}, True])
    def test_non_string_conditions_are_refused(self, condition: Any) -> None:
        with pytest.raises(ConditionSyntaxError, match="must be a string or list"):
            parse_condition(condition)

    def test_unclosed_parenthesis_is_refused(self) -> None:
        with pytest.raises(ConditionSyntaxError, match="expected rparen"):
            parse_condition("(a and b")

    def test_unbalanced_closing_parenthesis_is_refused(self) -> None:
        with pytest.raises(ConditionSyntaxError, match="unexpected"):
            parse_condition("a and b)")

    def test_trailing_operator_is_refused(self) -> None:
        with pytest.raises(ConditionSyntaxError):
            parse_condition("a and")

    def test_leading_operator_is_refused(self) -> None:
        with pytest.raises(ConditionSyntaxError):
            parse_condition("and a")

    def test_two_adjacent_identifiers_are_refused(self) -> None:
        with pytest.raises(ConditionSyntaxError, match="unexpected"):
            parse_condition("a b")

    def test_empty_parentheses_are_refused(self) -> None:
        with pytest.raises(ConditionSyntaxError):
            parse_condition("()")

    def test_source_label_is_included_in_errors(self) -> None:
        with pytest.raises(ConditionSyntaxError, match=re.escape("SDEL-TST-001.condition")):
            parse_condition("a and", source="SDEL-TST-001.condition")

    def test_parenthesis_depth_limit_is_enforced(self) -> None:
        depth = MAX_PAREN_DEPTH + 2
        with pytest.raises(ConditionSyntaxError, match="parenthesis nesting"):
            parse_condition("(" * depth + "a" + ")" * depth)

    def test_error_type_is_preserved_when_relabelled(self) -> None:
        with pytest.raises(UnsupportedConditionError):
            parse_condition("a | count()", source="rule.condition")


class TestParseConditionList:
    def test_list_of_conditions_is_a_disjunction(self) -> None:
        node = parse_condition(["a", "b"])
        assert isinstance(node, OrNode) and len(node.operands) == 2

    def test_single_element_list_collapses(self) -> None:
        assert parse_condition(["a"]) == SelectionRef("a")

    def test_tuple_is_accepted(self) -> None:
        assert isinstance(parse_condition(("a", "b")), OrNode)

    def test_list_element_errors_are_indexed(self) -> None:
        with pytest.raises(ConditionSyntaxError, match=r"\[1\]"):
            parse_condition(["a", "b and"])


class TestEvaluation:
    def test_selection_reference_uses_the_resolver(self) -> None:
        assert evaluate("a", {"a": True}) is True
        assert evaluate("a", {"a": False}) is False

    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [(True, True, True), (True, False, False), (False, True, False), (False, False, False)],
    )
    def test_and_truth_table(self, left: bool, right: bool, expected: bool) -> None:
        assert evaluate("a and b", {"a": left, "b": right}) is expected

    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [(True, True, True), (True, False, True), (False, True, True), (False, False, False)],
    )
    def test_or_truth_table(self, left: bool, right: bool, expected: bool) -> None:
        assert evaluate("a or b", {"a": left, "b": right}) is expected

    def test_not_inverts(self) -> None:
        assert evaluate("not a", {"a": False}) is True

    def test_precedence_is_respected_during_evaluation(self) -> None:
        truths = {"a": True, "b": False, "c": False}
        assert evaluate("a or b and c", truths) is True
        assert evaluate("(a or b) and c", truths) is False

    def test_common_selection_and_filter_shape(self) -> None:
        truths = {"selection": True, "filter": True}
        assert evaluate("selection and not filter", truths) is False
        truths["filter"] = False
        assert evaluate("selection and not filter", truths) is True

    def test_one_of_them_is_a_disjunction(self) -> None:
        assert evaluate("1 of them", {"a": False, "b": True}) is True

    def test_all_of_them_is_a_conjunction(self) -> None:
        assert evaluate("all of them", {"a": True, "b": False}) is False

    def test_prefix_pattern_selects_matching_names_only(self) -> None:
        truths = {"selection_a": False, "selection_b": True, "filter_a": True}
        assert evaluate("1 of selection_*", truths) is True
        assert evaluate("all of selection_*", truths) is False

    def test_prefix_pattern_with_no_match_raises(self) -> None:
        node = parse_condition("1 of missing_*")
        with pytest.raises(UnsupportedConditionError, match="no selection matches"):
            node.evaluate(lambda name: True, ("selection",))

    def test_unmatched_pattern_error_lists_defined_selections(self) -> None:
        node = parse_condition("all of nope_*")
        with pytest.raises(UnsupportedConditionError, match="selection_one"):
            node.evaluate(lambda name: True, ("selection_one",))

    def test_evaluation_is_short_circuit_free_for_correctness(self) -> None:
        seen: list[str] = []

        def resolver(name: str) -> bool:
            seen.append(name)
            return True

        parse_condition("a and b").evaluate(resolver, ("a", "b"))
        assert seen == ["a", "b"]


class TestReferencedSelections:
    def test_plain_reference_is_reported(self) -> None:
        assert parse_condition("a").referenced_selections(("a", "b")) == ("a",)

    def test_composite_condition_reports_every_name(self) -> None:
        names = parse_condition("a and (b or not c)").referenced_selections(("a", "b", "c"))
        assert set(names) == {"a", "b", "c"}

    def test_duplicates_are_reported_once(self) -> None:
        assert parse_condition("a and a").referenced_selections(("a",)) == ("a",)

    def test_them_expands_to_every_available_name(self) -> None:
        names = parse_condition("all of them").referenced_selections(("x", "y"))
        assert set(names) == {"x", "y"}

    def test_prefix_pattern_expands_to_matching_names(self) -> None:
        names = parse_condition("1 of sel_*").referenced_selections(("sel_a", "sel_b", "other"))
        assert set(names) == {"sel_a", "sel_b"}

    def test_unmatched_pattern_reports_nothing(self) -> None:
        assert parse_condition("1 of nope_*").referenced_selections(("sel",)) == ()


class TestRender:
    @pytest.mark.parametrize(
        "condition",
        [
            "selection",
            "a and b",
            "a or b",
            "1 of them",
            "all of them",
            "1 of selection_*",
        ],
    )
    def test_render_round_trips_simple_conditions(self, condition: str) -> None:
        assert parse_condition(condition).render() == condition

    def test_render_parenthesises_nested_composites(self) -> None:
        assert parse_condition("a or b and c").render() == "a or (b and c)"

    def test_render_of_not_wraps_composite_operands(self) -> None:
        assert parse_condition("not (a and b)").render() == "not (a and b)"

    def test_rendered_text_reparses_to_the_same_tree(self) -> None:
        original = parse_condition("(a or b) and not c")
        assert parse_condition(original.render()) == original

    def test_str_uses_render(self) -> None:
        assert str(parse_condition("a and b")) == "a and b"


class TestAstHelpers:
    def test_build_and_collapses_single_operand(self) -> None:
        assert build_and([SelectionRef("a")]) == SelectionRef("a")

    def test_build_or_collapses_single_operand(self) -> None:
        assert build_or([SelectionRef("a")]) == SelectionRef("a")

    def test_build_and_rejects_no_operands(self) -> None:
        with pytest.raises(UnsupportedConditionError):
            build_and([])

    def test_build_or_rejects_no_operands(self) -> None:
        with pytest.raises(UnsupportedConditionError):
            build_or([])

    def test_walk_yields_the_whole_tree(self) -> None:
        node = parse_condition("a and (b or c)")
        assert len(list(node.walk())) == 5

    def test_children_of_a_leaf_is_empty(self) -> None:
        assert SelectionRef("a").children() == ()

    def test_children_of_not_is_its_operand(self) -> None:
        node = NotNode(SelectionRef("a"))
        assert node.children() == (SelectionRef("a"),)

    def test_nodes_are_comparable_by_value(self) -> None:
        assert parse_condition("a and b") == parse_condition("a and b")

    def test_nodes_are_hashable(self) -> None:
        assert len({parse_condition("a"), parse_condition("a")}) == 1

    def test_quantifier_enum_renders_its_value(self) -> None:
        assert str(Quantifier.ALL) == "all" and str(Quantifier.ONE) == "1"

    def test_describe_indents_nested_nodes(self) -> None:
        lines = describe(parse_condition("a and b"))
        assert lines[0] == "and" and lines[1].startswith("  ")

    def test_describe_labels_selections(self) -> None:
        assert describe(SelectionRef("sel")) == ["selection sel"]

    def test_describe_labels_quantifiers(self) -> None:
        assert describe(parse_condition("1 of them")) == ["quantifier 1 of them"]

    def test_describe_handles_negation(self) -> None:
        assert describe(parse_condition("not a")) == ["not", "  selection a"]

    def test_describe_handles_disjunction(self) -> None:
        assert describe(parse_condition("a or b"))[0] == "or"

    def test_condition_node_is_abstract(self) -> None:
        with pytest.raises(TypeError):
            ConditionNode()  # type: ignore[abstract]


class TestIsSupportedCondition:
    @pytest.mark.parametrize(
        "condition",
        ["selection", "a and not b", "1 of them", "all of sel_*", ["a", "b"]],
    )
    def test_supported_conditions_return_true(self, condition: object) -> None:
        assert is_supported_condition(condition) is True

    @pytest.mark.parametrize(
        "condition",
        ["", None, "a |count()", "a near b", "selection_*", "a and", 42],
    )
    def test_unsupported_conditions_return_false(self, condition: object) -> None:
        assert is_supported_condition(condition) is False
