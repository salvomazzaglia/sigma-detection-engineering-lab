"""Console formatting helpers.

Plain text with no third-party dependency. Colour is emitted only when the stream
is an interactive terminal and ``NO_COLOR`` is unset, so redirected output and CI
logs stay clean and diffable.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final, TextIO

RESET: Final[str] = "\033[0m"
COLORS: Final[dict[str, str]] = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
    "bold": "\033[1m",
}

SEVERITY_COLORS: Final[dict[str, str]] = {
    "informational": "grey",
    "low": "cyan",
    "medium": "yellow",
    "high": "magenta",
    "critical": "red",
}

OUTCOME_COLORS: Final[dict[str, str]] = {
    "passed": "green",
    "failed": "red",
    "error": "red",
    "skipped": "grey",
    "unsupported": "yellow",
}

MIN_WIDTH: Final[int] = 40
MAX_WIDTH: Final[int] = 200
MAX_CELL_WIDTH: Final[int] = 80


def supports_color(stream: TextIO | None = None) -> bool:
    """Return whether ANSI colour should be emitted to ``stream``."""
    target = stream or sys.stdout
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(target, "isatty", lambda: False)())


def colorize(text: str, color: str | None, *, stream: TextIO | None = None) -> str:
    """Wrap ``text`` in an ANSI colour when the stream supports it."""
    if not color or color not in COLORS or not supports_color(stream):
        return text
    return f"{COLORS[color]}{text}{RESET}"


def terminal_width(default: int = 100) -> int:
    """Return a sane terminal width, clamped to readable bounds."""
    try:
        width = shutil.get_terminal_size((default, 24)).columns
    except OSError:  # pragma: no cover - defensive
        width = default
    return max(MIN_WIDTH, min(MAX_WIDTH, width))


def truncate(value: object, limit: int = MAX_CELL_WIDTH) -> str:
    """Render a value as a single line, truncated with an ellipsis if long.

    The ellipsis is three ASCII dots rather than U+2026 so the output survives a
    legacy console code page intact. A report that renders as mojibake is worse
    than one that renders plainly.
    """
    text = " ".join(str(value).split())
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def render_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    max_cell_width: int = MAX_CELL_WIDTH,
    empty_message: str = "(no rows)",
) -> str:
    """Render a fixed-width text table.

    Columns are sized to their widest cell so output stays aligned when piped to
    a file, which ANSI-based renderers do not guarantee.
    """
    if not rows:
        return empty_message

    rendered_rows = [[truncate(cell, max_cell_width) for cell in row] for row in rows]
    rendered_headers = [truncate(header, max_cell_width) for header in headers]

    widths = [len(header) for header in rendered_headers]
    for row in rendered_rows:
        for index, cell in enumerate(row):
            if index < len(widths):
                widths[index] = max(widths[index], len(cell))

    def line(cells: Sequence[str]) -> str:
        padded = [
            cell.ljust(widths[index]) if index < len(widths) else cell
            for index, cell in enumerate(cells)
        ]
        return "  ".join(padded).rstrip()

    separator = "  ".join("-" * width for width in widths)
    return "\n".join([line(rendered_headers), separator, *(line(row) for row in rendered_rows)])


def print_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    stream: TextIO | None = None,
    max_cell_width: int = MAX_CELL_WIDTH,
    empty_message: str = "(no rows)",
) -> None:
    """Print a table to ``stream``."""
    target = stream or sys.stdout
    print(
        render_table(headers, rows, max_cell_width=max_cell_width, empty_message=empty_message),
        file=target,
    )


def heading(text: str, *, stream: TextIO | None = None) -> str:
    """Render a section heading with an underline."""
    return colorize(f"{text}\n{'=' * len(text)}", "bold", stream=stream)


def subheading(text: str, *, stream: TextIO | None = None) -> str:
    """Render a subsection heading."""
    return colorize(f"{text}\n{'-' * len(text)}", "bold", stream=stream)


def banner(text: str, *, stream: TextIO | None = None) -> str:
    """Render a disclosure banner inside a box, so it cannot be skimmed past."""
    width = min(terminal_width(), max(len(text) + 4, 20))
    inner = width - 4
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= inner:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)

    border = "+" + "-" * (width - 2) + "+"
    body = [f"| {line.ljust(inner)} |" for line in lines]
    return colorize("\n".join([border, *body, border]), "yellow", stream=stream)


def key_values(
    mapping: Mapping[str, Any],
    *,
    indent: str = "  ",
    separator: str = ": ",
) -> str:
    """Render a mapping as aligned ``key: value`` lines."""
    if not mapping:
        return f"{indent}(empty)"
    width = max(len(str(key)) for key in mapping)
    return "\n".join(
        f"{indent}{str(key).ljust(width)}{separator}{value}" for key, value in mapping.items()
    )


def bullet_list(items: Iterable[Any], *, indent: str = "  ", marker: str = "-") -> str:
    """Render an iterable as a bullet list."""
    rendered = [f"{indent}{marker} {item}" for item in items]
    return "\n".join(rendered) if rendered else f"{indent}(none)"


def severity_label(severity: str, *, stream: TextIO | None = None) -> str:
    """Render a severity name in its conventional colour."""
    return colorize(
        severity.upper().ljust(13), SEVERITY_COLORS.get(severity.lower()), stream=stream
    )


def outcome_label(outcome: str, *, stream: TextIO | None = None) -> str:
    """Render a test outcome in its conventional colour."""
    return colorize(outcome.upper().ljust(11), OUTCOME_COLORS.get(outcome.lower()), stream=stream)


def status_line(passed: bool, text: str, *, stream: TextIO | None = None) -> str:
    """Render a pass/fail line with a leading marker."""
    marker = "PASS" if passed else "FAIL"
    return f"{colorize(marker, 'green' if passed else 'red', stream=stream)}  {text}"


def write(text: str, *, stream: TextIO | None = None) -> None:
    """Print a block of text to ``stream``."""
    print(text, file=stream or sys.stdout)


def blank(*, stream: TextIO | None = None) -> None:
    """Print an empty line."""
    print(file=stream or sys.stdout)


__all__ = [
    "COLORS",
    "MAX_CELL_WIDTH",
    "OUTCOME_COLORS",
    "RESET",
    "SEVERITY_COLORS",
    "banner",
    "blank",
    "bullet_list",
    "colorize",
    "heading",
    "key_values",
    "outcome_label",
    "print_table",
    "render_table",
    "severity_label",
    "status_line",
    "subheading",
    "supports_color",
    "terminal_width",
    "truncate",
    "write",
]
