"""Tokeniser and recursive-descent parser for the supported condition subset.

Precedence follows the Sigma specification: ``not`` binds tightest, then ``and``,
then ``or``. Anything outside the documented fragment raises
:class:`~sigma_detection_engineering_lab.errors.UnsupportedConditionError` with a
message naming the construct, so a rule author is told what to change rather than
receiving a silently wrong evaluation.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Final

from sigma_detection_engineering_lab.condition_model import (
    ConditionNode,
    NotNode,
    QuantifiedSelection,
    Quantifier,
    SelectionRef,
    build_and,
    build_or,
)
from sigma_detection_engineering_lab.errors import (
    ConditionSyntaxError,
    UnsupportedConditionError,
)

MAX_CONDITION_LENGTH: Final[int] = 2048
MAX_TOKENS: Final[int] = 512
MAX_PAREN_DEPTH: Final[int] = 32

AGGREGATION_KEYWORDS: Final[frozenset[str]] = frozenset(
    {"count", "min", "max", "avg", "sum", "near"}
)
"""Recognised specifically so the error message can name the unsupported feature."""

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-]*\*?")
_WHITESPACE = re.compile(r"\s+")


class TokenType(str, Enum):
    IDENT = "ident"
    AND = "and"
    OR = "or"
    NOT = "not"
    OF = "of"
    ONE = "one"
    ALL = "all"
    THEM = "them"
    LPAREN = "lparen"
    RPAREN = "rparen"
    EOF = "eof"


@dataclass(frozen=True)
class Token:
    """One lexical token with its source offset, used in error messages."""

    type: TokenType
    text: str
    position: int


_KEYWORDS: Final[dict[str, TokenType]] = {
    "and": TokenType.AND,
    "or": TokenType.OR,
    "not": TokenType.NOT,
    "of": TokenType.OF,
    "all": TokenType.ALL,
    "them": TokenType.THEM,
}


def tokenize(text: str) -> list[Token]:
    """Convert condition text into tokens.

    Raises:
        ConditionSyntaxError: on an unexpected character or an oversized input.
        UnsupportedConditionError: on aggregation and comparison syntax.
    """
    if len(text) > MAX_CONDITION_LENGTH:
        raise ConditionSyntaxError(
            f"condition length {len(text)} exceeds limit {MAX_CONDITION_LENGTH}"
        )

    tokens: list[Token] = []
    index = 0
    length = len(text)
    while index < length:
        whitespace = _WHITESPACE.match(text, index)
        if whitespace:
            index = whitespace.end()
            continue

        char = text[index]
        if char == "(":
            tokens.append(Token(TokenType.LPAREN, "(", index))
            index += 1
        elif char == ")":
            tokens.append(Token(TokenType.RPAREN, ")", index))
            index += 1
        elif char == "|":
            raise UnsupportedConditionError(
                f"aggregation pipe '|' at position {index} is outside the supported subset; "
                "the lab evaluator implements no aggregations"
            )
        elif char in "<>=!":
            raise UnsupportedConditionError(
                f"comparison operator {char!r} at position {index} is outside the supported "
                "subset; gt/gte/lt/lte are not implemented"
            )
        elif char == "1" and _is_quantifier_one(text, index):
            tokens.append(Token(TokenType.ONE, "1", index))
            index += 1
        else:
            match = _IDENTIFIER.match(text, index)
            if not match:
                raise ConditionSyntaxError(
                    f"unexpected character {char!r} at position {index} in condition {text!r}"
                )
            word = match.group(0)
            lowered = word.lower()
            if lowered in AGGREGATION_KEYWORDS and lowered != "near":
                raise UnsupportedConditionError(
                    f"aggregation function {word!r} at position {index} is outside the "
                    "supported subset"
                )
            if lowered == "near":
                raise UnsupportedConditionError(
                    f"'near' at position {index} is outside the supported subset; use a "
                    "correlation rule of type temporal instead"
                )
            token_type = _KEYWORDS.get(lowered, TokenType.IDENT)
            tokens.append(Token(token_type, word, index))
            index = match.end()

        if len(tokens) > MAX_TOKENS:
            raise ConditionSyntaxError(f"condition token count exceeds limit {MAX_TOKENS}")

    tokens.append(Token(TokenType.EOF, "", length))
    return tokens


def _is_quantifier_one(text: str, index: int) -> bool:
    """Return whether the digit at ``index`` begins a ``1 of ...`` expression."""
    remainder = text[index + 1 :]
    if remainder[:1].isdigit():
        return False
    return _WHITESPACE.match(remainder) is not None and remainder.lstrip().lower().startswith("of")


class _Parser:
    """Recursive-descent parser over the token stream."""

    def __init__(self, tokens: Sequence[Token], source: str) -> None:
        self._tokens = list(tokens)
        self._index = 0
        self._source = source
        self._depth = 0

    @property
    def current(self) -> Token:
        return self._tokens[self._index]

    def advance(self) -> Token:
        token = self._tokens[self._index]
        if token.type is not TokenType.EOF:
            self._index += 1
        return token

    @staticmethod
    def _describe(token: Token) -> str:
        return repr(token.text) if token.text else "end of input"

    def expect(self, token_type: TokenType) -> Token:
        token = self.current
        if token.type is not token_type:
            raise ConditionSyntaxError(
                f"expected {token_type.value} at position {token.position} in "
                f"{self._source!r}, found {self._describe(token)}"
            )
        return self.advance()

    def parse(self) -> ConditionNode:
        if self.current.type is TokenType.EOF:
            raise ConditionSyntaxError(f"condition is empty: {self._source!r}")
        node = self.parse_or()
        trailing = self.current
        if trailing.type is not TokenType.EOF:
            raise ConditionSyntaxError(
                f"unexpected {trailing.text!r} at position {trailing.position} in {self._source!r}"
            )
        return node

    def parse_or(self) -> ConditionNode:
        operands = [self.parse_and()]
        while self.current.type is TokenType.OR:
            self.advance()
            operands.append(self.parse_and())
        return build_or(operands)

    def parse_and(self) -> ConditionNode:
        operands = [self.parse_not()]
        while self.current.type is TokenType.AND:
            self.advance()
            operands.append(self.parse_not())
        return build_and(operands)

    def parse_not(self) -> ConditionNode:
        if self.current.type is TokenType.NOT:
            self.advance()
            return NotNode(self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> ConditionNode:
        token = self.current
        if token.type is TokenType.LPAREN:
            self.advance()
            self._depth += 1
            if self._depth > MAX_PAREN_DEPTH:
                raise ConditionSyntaxError(
                    f"parenthesis nesting exceeds limit {MAX_PAREN_DEPTH} in {self._source!r}"
                )
            node = self.parse_or()
            self.expect(TokenType.RPAREN)
            self._depth -= 1
            return node

        if token.type in (TokenType.ONE, TokenType.ALL):
            return self.parse_quantified()

        if token.type is TokenType.IDENT:
            self.advance()
            if token.text.endswith("*"):
                raise UnsupportedConditionError(
                    f"bare wildcard selection {token.text!r} at position {token.position} is not "
                    "supported; write '1 of <prefix>*' or 'all of <prefix>*'"
                )
            return SelectionRef(token.text)

        if token.type is TokenType.THEM:
            raise ConditionSyntaxError(
                f"'them' at position {token.position} must follow '1 of' or 'all of'"
            )

        raise ConditionSyntaxError(
            f"unexpected {self._describe(token)} at position {token.position} in {self._source!r}"
        )

    def parse_quantified(self) -> ConditionNode:
        token = self.advance()
        quantifier = Quantifier.ONE if token.type is TokenType.ONE else Quantifier.ALL

        if self.current.type is not TokenType.OF:
            # "all" is also a legal selection name; treat it as one when not
            # followed by "of", but only for the ALL token.
            if quantifier is Quantifier.ALL:
                return SelectionRef(token.text)
            raise ConditionSyntaxError(
                f"expected 'of' after '1' at position {token.position} in {self._source!r}"
            )
        self.advance()

        target = self.current
        if target.type is TokenType.THEM:
            self.advance()
            return QuantifiedSelection(quantifier, "them")
        if target.type is not TokenType.IDENT:
            raise ConditionSyntaxError(
                f"expected a selection pattern after 'of' at position {target.position} in "
                f"{self._source!r}"
            )
        self.advance()
        pattern = target.text
        if "*" in pattern[:-1]:
            raise UnsupportedConditionError(
                f"selection pattern {pattern!r} at position {target.position} uses an interior "
                "wildcard; only a trailing '*' prefix pattern is supported"
            )
        return QuantifiedSelection(quantifier, pattern)


def parse_condition(condition: object, *, source: str = "detection.condition") -> ConditionNode:
    """Parse a Sigma condition into an AST.

    A list of conditions is treated as a disjunction, matching the Sigma
    specification's handling of multiple conditions.

    Args:
        condition: The raw ``detection.condition`` value: a string, or a list of
            strings meaning "any of these".
        source: Label used in error messages.

    Returns:
        The parsed condition tree.

    Raises:
        ConditionSyntaxError: if the condition is missing, empty, or malformed.
        UnsupportedConditionError: if it uses a construct outside the subset.
    """
    if condition is None:
        raise ConditionSyntaxError(f"{source}: condition is required")

    if isinstance(condition, (list, tuple)):
        if not condition:
            raise ConditionSyntaxError(f"{source}: condition list is empty")
        branches = [
            parse_condition(item, source=f"{source}[{index}]")
            for index, item in enumerate(condition)
        ]
        return build_or(branches)

    if not isinstance(condition, str):
        raise ConditionSyntaxError(
            f"{source}: condition must be a string or list of strings, "
            f"got {type(condition).__name__}"
        )

    text = condition.strip()
    if not text:
        raise ConditionSyntaxError(f"{source}: condition is empty")

    try:
        tokens = tokenize(text)
    except (ConditionSyntaxError, UnsupportedConditionError) as exc:
        raise type(exc)(f"{source}: {exc}") from exc

    try:
        return _Parser(tokens, text).parse()
    except (ConditionSyntaxError, UnsupportedConditionError) as exc:
        raise type(exc)(f"{source}: {exc}") from exc


def is_supported_condition(condition: object) -> bool:
    """Return whether a condition parses within the supported subset."""
    try:
        parse_condition(condition)
    except (ConditionSyntaxError, UnsupportedConditionError):
        return False
    return True


__all__ = [
    "AGGREGATION_KEYWORDS",
    "MAX_CONDITION_LENGTH",
    "MAX_PAREN_DEPTH",
    "MAX_TOKENS",
    "Token",
    "TokenType",
    "is_supported_condition",
    "parse_condition",
    "tokenize",
]
