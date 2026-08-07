"""Hardened YAML loading.

Sigma rules are untrusted input. This module never uses ``yaml.load`` with a
permissive loader; it composes the node graph first, checks it against explicit
structural limits, and only then constructs Python objects.

Refusals applied here:

* only ``yaml.SafeLoader`` semantics, with an additional tag allowlist so
  ``!!python/...``, ``!!binary``, ``!!merge``, and custom application tags are
  rejected at compose time rather than construction time;
* duplicate mapping keys are an error, not a silent last-wins overwrite;
* aliases are limited (zero by default), which forecloses billion-laughs;
* depth, total node count, scalar length, mapping size, and sequence length
  are all bounded;
* NUL bytes in the source are rejected outright.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from sigma_detection_engineering_lab.errors import YamlSafetyError
from sigma_detection_engineering_lab.paths import DEFAULT_MAX_FILE_BYTES, safe_read_text

ALLOWED_TAGS: Final[frozenset[str]] = frozenset(
    {
        "tag:yaml.org,2002:map",
        "tag:yaml.org,2002:seq",
        "tag:yaml.org,2002:str",
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:null",
        "tag:yaml.org,2002:timestamp",
    }
)
"""Only plain data tags are permitted. Everything else is refused by name."""


@dataclass(frozen=True)
class YamlLimits:
    """Structural bounds applied to every YAML document.

    Defaults match ``config/default.config.json`` so the loader is safe even when
    used before configuration has been read.
    """

    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_depth: int = 32
    max_nodes: int = 5000
    max_aliases: int = 0
    max_scalar_length: int = 8192
    max_mapping_size: int = 512
    max_sequence_length: int = 512
    max_documents: int = 16


DEFAULT_LIMITS: Final[YamlLimits] = YamlLimits()


class _HardenedSafeLoader(yaml.SafeLoader):
    """SafeLoader subclass that counts aliases and rejects duplicate keys."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self.limits: YamlLimits = DEFAULT_LIMITS
        self.source: str = "<string>"
        self._alias_count: int = 0

    def compose_node(self, parent: Node | None, index: Any) -> Node | None:
        if self.check_event(AliasEvent):  # type: ignore[no-untyped-call]
            self._alias_count += 1
            if self._alias_count > self.limits.max_aliases:
                event = self.peek_event()  # type: ignore[no-untyped-call]
                raise YamlSafetyError(
                    f"{self.source}: alias count exceeds limit "
                    f"{self.limits.max_aliases} (alias {getattr(event, 'anchor', '?')!r}); "
                    "aliases are restricted to prevent expansion attacks"
                )
        return super().compose_node(parent, index)

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        seen: set[Any] = set()
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                hashable = key in seen
            except TypeError as exc:
                raise YamlSafetyError(
                    f"{self.source}: unhashable mapping key of type {type(key).__name__} "
                    f"at line {key_node.start_mark.line + 1}"
                ) from exc
            if hashable:
                raise YamlSafetyError(
                    f"{self.source}: duplicate mapping key {key!r} at line "
                    f"{key_node.start_mark.line + 1}; duplicate keys are rejected because "
                    "silent overwrite changes detection logic"
                )
            seen.add(key)
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _describe(node: Node) -> str:
    mark = node.start_mark
    return f"line {mark.line + 1}, column {mark.column + 1}"


def _validate_node(node: Node, limits: YamlLimits, source: str) -> None:
    """Walk the composed node graph, enforcing every structural limit."""
    total = 0
    # Explicit stack rather than recursion: depth is attacker-influenced and a
    # recursive walk would hit the interpreter limit before ours.
    stack: list[tuple[Node, int]] = [(node, 1)]
    while stack:
        current, depth = stack.pop()
        total += 1
        if total > limits.max_nodes:
            raise YamlSafetyError(f"{source}: node count exceeds limit {limits.max_nodes}")
        if depth > limits.max_depth:
            raise YamlSafetyError(
                f"{source}: nesting depth exceeds limit {limits.max_depth} at {_describe(current)}"
            )
        if current.tag not in ALLOWED_TAGS:
            raise YamlSafetyError(
                f"{source}: forbidden YAML tag {current.tag!r} at {_describe(current)}; "
                f"only plain data tags are accepted"
            )
        if isinstance(current, ScalarNode):
            if len(current.value) > limits.max_scalar_length:
                raise YamlSafetyError(
                    f"{source}: scalar length {len(current.value)} exceeds limit "
                    f"{limits.max_scalar_length} at {_describe(current)}"
                )
        elif isinstance(current, SequenceNode):
            if len(current.value) > limits.max_sequence_length:
                raise YamlSafetyError(
                    f"{source}: sequence length {len(current.value)} exceeds limit "
                    f"{limits.max_sequence_length} at {_describe(current)}"
                )
            for child in current.value:
                stack.append((child, depth + 1))
        elif isinstance(current, MappingNode):
            if len(current.value) > limits.max_mapping_size:
                raise YamlSafetyError(
                    f"{source}: mapping size {len(current.value)} exceeds limit "
                    f"{limits.max_mapping_size} at {_describe(current)}"
                )
            for key_node, value_node in current.value:
                stack.append((key_node, depth + 1))
                stack.append((value_node, depth + 1))
        else:  # pragma: no cover - PyYAML defines no other node types
            raise YamlSafetyError(
                f"{source}: unexpected node type {type(current).__name__} at {_describe(current)}"
            )


def _check_raw_text(text: str, limits: YamlLimits, source: str) -> None:
    if "\x00" in text:
        raise YamlSafetyError(f"{source}: NUL byte in YAML source is rejected")
    encoded_length = len(text.encode("utf-8"))
    if encoded_length > limits.max_file_bytes:
        raise YamlSafetyError(
            f"{source}: document size {encoded_length} exceeds limit {limits.max_file_bytes}"
        )


def load_documents(
    text: str,
    *,
    limits: YamlLimits = DEFAULT_LIMITS,
    source: str = "<string>",
) -> list[Any]:
    """Load every document in a YAML stream under the given limits.

    Args:
        text: Raw YAML source.
        limits: Structural bounds to enforce.
        source: Label used in error messages, normally a relative file path.

    Returns:
        One entry per YAML document, in stream order.

    Raises:
        YamlSafetyError: on any limit violation, forbidden tag, duplicate key,
            or underlying parse error.
    """
    _check_raw_text(text, limits, source)

    loader = _HardenedSafeLoader(text)
    loader.limits = limits
    loader.source = source
    documents: list[Any] = []
    try:
        while loader.check_node():
            if len(documents) >= limits.max_documents:
                raise YamlSafetyError(
                    f"{source}: document count exceeds limit {limits.max_documents}"
                )
            node = loader.get_node()
            if node is None:  # pragma: no cover - check_node guards this
                break
            _validate_node(node, limits, source)
            documents.append(loader.construct_document(node))  # type: ignore[no-untyped-call]
    except yaml.YAMLError as exc:
        raise YamlSafetyError(f"{source}: invalid YAML: {exc}") from exc
    finally:
        loader.dispose()  # type: ignore[no-untyped-call]
    return documents


def load_single_document(
    text: str,
    *,
    limits: YamlLimits = DEFAULT_LIMITS,
    source: str = "<string>",
) -> Any:
    """Load exactly one YAML document.

    Raises:
        YamlSafetyError: if the stream is empty or holds more than one document.
    """
    documents = load_documents(text, limits=limits, source=source)
    if len(documents) != 1:
        raise YamlSafetyError(
            f"{source}: expected exactly one YAML document, found {len(documents)}"
        )
    return documents[0]


def require_mapping(document: Any, *, source: str = "<string>") -> dict[str, Any]:
    """Assert that a loaded document is a mapping with string keys.

    Raises:
        YamlSafetyError: if the root is not a mapping or has a non-string key.
    """
    if not isinstance(document, dict):
        raise YamlSafetyError(
            f"{source}: document root must be a mapping, got {type(document).__name__}"
        )
    for key in document:
        if not isinstance(key, str):
            raise YamlSafetyError(
                f"{source}: mapping keys at document root must be strings, "
                f"got {type(key).__name__} ({key!r})"
            )
    return dict(document)


def load_single_mapping(
    text: str,
    *,
    limits: YamlLimits = DEFAULT_LIMITS,
    source: str = "<string>",
) -> dict[str, Any]:
    """Load one YAML document and require its root to be a string-keyed mapping."""
    return require_mapping(load_single_document(text, limits=limits, source=source), source=source)


def load_mapping_documents(
    text: str,
    *,
    limits: YamlLimits = DEFAULT_LIMITS,
    source: str = "<string>",
) -> list[dict[str, Any]]:
    """Load a multi-document stream where every document must be a mapping.

    Sigma correlation rules ship as multi-document files, so this is the entry
    point used by the rule loader.

    Raises:
        YamlSafetyError: if the stream is empty or any document is not a mapping.
    """
    documents = load_documents(text, limits=limits, source=source)
    if not documents:
        raise YamlSafetyError(f"{source}: YAML stream contains no documents")
    return [
        require_mapping(document, source=f"{source}[document {index}]")
        for index, document in enumerate(documents)
    ]


def load_yaml_file(
    path: Path,
    *,
    limits: YamlLimits = DEFAULT_LIMITS,
    source: str | None = None,
) -> list[Any]:
    """Read and safely load all documents from a YAML file."""
    label = source if source is not None else path.as_posix()
    text = safe_read_text(path, max_bytes=limits.max_file_bytes)
    return load_documents(text, limits=limits, source=label)


def load_mapping_file(
    path: Path,
    *,
    limits: YamlLimits = DEFAULT_LIMITS,
    source: str | None = None,
) -> dict[str, Any]:
    """Read a YAML file expected to hold a single mapping document."""
    label = source if source is not None else path.as_posix()
    text = safe_read_text(path, max_bytes=limits.max_file_bytes)
    return load_single_mapping(text, limits=limits, source=label)


def load_mapping_documents_file(
    path: Path,
    *,
    limits: YamlLimits = DEFAULT_LIMITS,
    source: str | None = None,
) -> list[dict[str, Any]]:
    """Read a possibly multi-document YAML file where every document is a mapping."""
    label = source if source is not None else path.as_posix()
    text = safe_read_text(path, max_bytes=limits.max_file_bytes)
    return load_mapping_documents(text, limits=limits, source=label)


def dump_safe(data: Any, *, sort_keys: bool = False) -> str:
    """Serialise plain data back to YAML using the safe dumper.

    Used only for generated demo content; anchors and aliases are disabled so
    round-tripped output stays loadable under the same limits.
    """
    return yaml.safe_dump(
        data,
        sort_keys=sort_keys,
        allow_unicode=True,
        default_flow_style=False,
        width=100,
    )


def limits_from_mapping(values: dict[str, Any]) -> YamlLimits:
    """Build :class:`YamlLimits` from a configuration ``limits`` mapping.

    Unknown keys are ignored so the shared limits block can carry entries that
    only other subsystems care about.
    """
    return YamlLimits(
        max_file_bytes=int(values.get("max_file_bytes", DEFAULT_LIMITS.max_file_bytes)),
        max_depth=int(values.get("max_yaml_depth", DEFAULT_LIMITS.max_depth)),
        max_nodes=int(values.get("max_yaml_nodes", DEFAULT_LIMITS.max_nodes)),
        max_aliases=int(values.get("max_yaml_aliases", DEFAULT_LIMITS.max_aliases)),
        max_scalar_length=int(values.get("max_scalar_length", DEFAULT_LIMITS.max_scalar_length)),
        max_mapping_size=int(values.get("max_mapping_size", DEFAULT_LIMITS.max_mapping_size)),
        max_sequence_length=int(
            values.get("max_sequence_length", DEFAULT_LIMITS.max_sequence_length)
        ),
    )


def allowed_tags() -> Sequence[str]:
    """Return the sorted tag allowlist, for documentation and tests."""
    return sorted(ALLOWED_TAGS)


__all__ = [
    "ALLOWED_TAGS",
    "DEFAULT_LIMITS",
    "YamlLimits",
    "allowed_tags",
    "dump_safe",
    "limits_from_mapping",
    "load_documents",
    "load_mapping_documents",
    "load_mapping_documents_file",
    "load_mapping_file",
    "load_single_document",
    "load_single_mapping",
    "load_yaml_file",
    "require_mapping",
]
