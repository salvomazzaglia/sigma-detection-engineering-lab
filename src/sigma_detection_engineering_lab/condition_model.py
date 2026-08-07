"""Abstract syntax tree for the supported Sigma condition subset.

The laboratory implements a documented fragment of the Sigma condition grammar:
``and``, ``or``, ``not``, parentheses, named selections, ``1 of prefix*``, and
``all of prefix*`` (including the ``them`` forms). Aggregations, ``near``, and
arbitrary expressions are outside the fragment and are refused by the parser
rather than approximated, because an approximated condition would produce test
results that do not mean what they appear to mean.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from enum import Enum

from sigma_detection_engineering_lab.errors import UnsupportedConditionError


class Quantifier(str, Enum):
    """Quantifier in a ``1 of ...`` or ``all of ...`` expression."""

    ONE = "1"
    ALL = "all"

    def __str__(self) -> str:
        return self.value


class ConditionNode(ABC):
    """Base class for every condition AST node."""

    @abstractmethod
    def render(self) -> str:
        """Re-render this node as Sigma condition text."""

    @abstractmethod
    def children(self) -> Sequence[ConditionNode]:
        """Return direct child nodes, for generic traversal."""

    def walk(self) -> Iterator[ConditionNode]:
        """Yield this node and every descendant, depth first."""
        yield self
        for child in self.children():
            yield from child.walk()

    def referenced_selections(self, available: Sequence[str]) -> tuple[str, ...]:
        """Return every selection name this condition can reach.

        ``available`` supplies the selection names defined in the rule so that
        quantified patterns such as ``selection_*`` can be expanded.
        """
        found: list[str] = []
        for node in self.walk():
            if isinstance(node, SelectionRef):
                if node.name not in found:
                    found.append(node.name)
            elif isinstance(node, QuantifiedSelection):
                for name in node.resolve(available):
                    if name not in found:
                        found.append(name)
        return tuple(found)

    def evaluate(self, resolver: Callable[[str], bool], available: Sequence[str]) -> bool:
        """Evaluate the condition given a per-selection truth function.

        Args:
            resolver: Returns whether the named selection matched.
            available: Selection names defined by the rule, used to expand
                quantified patterns.
        """
        return self._evaluate(resolver, available)

    @abstractmethod
    def _evaluate(self, resolver: Callable[[str], bool], available: Sequence[str]) -> bool: ...

    def __str__(self) -> str:
        return self.render()


@dataclass(frozen=True)
class SelectionRef(ConditionNode):
    """A reference to a named detection selection."""

    name: str

    def render(self) -> str:
        return self.name

    def children(self) -> Sequence[ConditionNode]:
        return ()

    def _evaluate(self, resolver: Callable[[str], bool], available: Sequence[str]) -> bool:
        return resolver(self.name)


@dataclass(frozen=True)
class NotNode(ConditionNode):
    """Logical negation."""

    operand: ConditionNode

    def render(self) -> str:
        return f"not {_parenthesise(self.operand)}"

    def children(self) -> Sequence[ConditionNode]:
        return (self.operand,)

    def _evaluate(self, resolver: Callable[[str], bool], available: Sequence[str]) -> bool:
        return not self.operand.evaluate(resolver, available)


@dataclass(frozen=True)
class AndNode(ConditionNode):
    """Conjunction of two or more operands."""

    operands: tuple[ConditionNode, ...]

    def render(self) -> str:
        return " and ".join(_parenthesise(operand) for operand in self.operands)

    def children(self) -> Sequence[ConditionNode]:
        return self.operands

    def _evaluate(self, resolver: Callable[[str], bool], available: Sequence[str]) -> bool:
        return all(operand.evaluate(resolver, available) for operand in self.operands)


@dataclass(frozen=True)
class OrNode(ConditionNode):
    """Disjunction of two or more operands."""

    operands: tuple[ConditionNode, ...]

    def render(self) -> str:
        return " or ".join(_parenthesise(operand) for operand in self.operands)

    def children(self) -> Sequence[ConditionNode]:
        return self.operands

    def _evaluate(self, resolver: Callable[[str], bool], available: Sequence[str]) -> bool:
        return any(operand.evaluate(resolver, available) for operand in self.operands)


@dataclass(frozen=True)
class QuantifiedSelection(ConditionNode):
    """``1 of <pattern>`` or ``all of <pattern>``.

    ``pattern`` is either the literal ``them``, a prefix glob such as
    ``selection_*``, or a bare selection name. Only a trailing ``*`` is
    supported; an interior wildcard is rejected by the parser.
    """

    quantifier: Quantifier
    pattern: str

    @property
    def is_them(self) -> bool:
        return self.pattern == "them"

    def render(self) -> str:
        return f"{self.quantifier.value} of {self.pattern}"

    def children(self) -> Sequence[ConditionNode]:
        return ()

    def resolve(self, available: Sequence[str]) -> tuple[str, ...]:
        """Expand the pattern against the rule's defined selection names."""
        if self.is_them:
            return tuple(available)
        if self.pattern.endswith("*"):
            prefix = self.pattern[:-1]
            return tuple(name for name in available if name.startswith(prefix))
        return tuple(name for name in available if name == self.pattern)

    def _evaluate(self, resolver: Callable[[str], bool], available: Sequence[str]) -> bool:
        names = self.resolve(available)
        if not names:
            # An unmatched pattern is a rule authoring error, not a silent false.
            raise UnsupportedConditionError(
                f"condition references {self.render()!r} but no selection matches that pattern; "
                f"defined selections: {', '.join(available) or '(none)'}"
            )
        if self.quantifier is Quantifier.ALL:
            return all(resolver(name) for name in names)
        return any(resolver(name) for name in names)


def _parenthesise(node: ConditionNode) -> str:
    """Wrap composite nodes in parentheses so re-rendered text keeps its meaning."""
    if isinstance(node, (AndNode, OrNode)):
        return f"({node.render()})"
    return node.render()


def build_and(operands: Sequence[ConditionNode]) -> ConditionNode:
    """Build a conjunction, collapsing the single-operand case."""
    if not operands:
        raise UnsupportedConditionError("'and' requires at least one operand")
    if len(operands) == 1:
        return operands[0]
    return AndNode(tuple(operands))


def build_or(operands: Sequence[ConditionNode]) -> ConditionNode:
    """Build a disjunction, collapsing the single-operand case."""
    if not operands:
        raise UnsupportedConditionError("'or' requires at least one operand")
    if len(operands) == 1:
        return operands[0]
    return OrNode(tuple(operands))


def describe(node: ConditionNode, indent: int = 0) -> list[str]:
    """Render the AST as an indented tree, used by the ``explain`` command."""
    pad = "  " * indent
    if isinstance(node, SelectionRef):
        return [f"{pad}selection {node.name}"]
    if isinstance(node, QuantifiedSelection):
        return [f"{pad}quantifier {node.render()}"]
    if isinstance(node, NotNode):
        return [f"{pad}not", *describe(node.operand, indent + 1)]
    if isinstance(node, AndNode):
        lines = [f"{pad}and"]
        for operand in node.operands:
            lines.extend(describe(operand, indent + 1))
        return lines
    if isinstance(node, OrNode):
        lines = [f"{pad}or"]
        for operand in node.operands:
            lines.extend(describe(operand, indent + 1))
        return lines
    return [f"{pad}{node.render()}"]  # pragma: no cover - all node types covered


__all__ = [
    "AndNode",
    "ConditionNode",
    "NotNode",
    "OrNode",
    "QuantifiedSelection",
    "Quantifier",
    "SelectionRef",
    "build_and",
    "build_or",
    "describe",
]
