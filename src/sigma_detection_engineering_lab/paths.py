"""Project root resolution and filesystem containment guarantees.

Every file this package reads goes through :func:`safe_resolve`, which enforces
four properties: the target stays inside the project root, no component of the
path is a symbolic link, the path string is within a length bound, and the file
is within a byte-size bound. Rules, fixtures, and metadata are untrusted input
as far as this module is concerned.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Final

from sigma_detection_engineering_lab.constants import PROJECT_ROOT_MARKER
from sigma_detection_engineering_lab.errors import PathSafetyError

DEFAULT_MAX_PATH_LENGTH: Final[int] = 4096
DEFAULT_MAX_FILE_BYTES: Final[int] = 1_048_576

SECONDARY_ROOT_MARKERS: Final[tuple[str, ...]] = ("VERSION", "config")
"""Additional markers that raise confidence a directory is the project root."""


def _looks_like_root(candidate: Path, marker: str) -> bool:
    if not (candidate / marker).is_file():
        return False
    return any((candidate / extra).exists() for extra in SECONDARY_ROOT_MARKERS)


def find_project_root(
    start: Path | str | None = None,
    *,
    marker: str = PROJECT_ROOT_MARKER,
) -> Path:
    """Walk upward from ``start`` until a directory containing ``marker`` is found.

    Args:
        start: Directory or file to begin from. Defaults to the current working
            directory, then falls back to this module's own location so the
            package still resolves its root when invoked from elsewhere.
        marker: Filename identifying the project root.

    Returns:
        The absolute project root directory.

    Raises:
        PathSafetyError: if no ancestor of any candidate contains the marker.
    """
    candidates: list[Path] = []
    if start is not None:
        candidates.append(Path(start))
    else:
        candidates.append(Path.cwd())
    candidates.append(Path(__file__).resolve())

    strong: Path | None = None
    weak: Path | None = None
    for candidate in candidates:
        base = candidate if candidate.is_dir() else candidate.parent
        try:
            base = base.resolve()
        except OSError:  # pragma: no cover - unreachable on supported platforms
            continue
        for directory in (base, *base.parents):
            if not (directory / marker).is_file():
                continue
            if _looks_like_root(directory, marker):
                strong = directory
                break
            if weak is None:
                weak = directory
        if strong is not None:
            return strong

    if weak is not None:
        return weak
    searched = ", ".join(str(candidate) for candidate in candidates)
    raise PathSafetyError(
        f"could not locate project root: no ancestor of [{searched}] contains {marker!r}"
    )


def is_contained(root: Path, candidate: Path) -> bool:
    """Return whether ``candidate`` lies inside ``root`` (or is ``root`` itself)."""
    try:
        root_abs = root.absolute()
        candidate_abs = candidate.absolute()
    except OSError:  # pragma: no cover - defensive
        return False
    try:
        candidate_abs.relative_to(root_abs)
    except ValueError:
        return False
    return True


def ensure_contained(root: Path, candidate: Path) -> Path:
    """Return ``candidate`` unchanged, or raise if it escapes ``root``.

    Raises:
        PathSafetyError: if the candidate is outside the root.
    """
    if not is_contained(root, candidate):
        raise PathSafetyError(f"path escapes project root: {candidate} is not inside {root}")
    return candidate


def assert_no_symlink(root: Path, target: Path) -> None:
    """Reject ``target`` if it, or any component between it and ``root``, is a symlink.

    Symlinks are refused rather than followed: a repository under review must not
    be able to redirect the loader at content outside the tree.

    Raises:
        PathSafetyError: if a symbolic link is found on the path.
    """
    root_abs = root.absolute()
    node = target.absolute()
    seen: set[Path] = set()
    while True:
        if node in seen:  # pragma: no cover - guards against pathological loops
            break
        seen.add(node)
        if node.is_symlink():
            raise PathSafetyError(f"symbolic links are rejected: {node}")
        if node == root_abs or node.parent == node:
            break
        node = node.parent


def check_path_length(path: Path, *, max_path_length: int = DEFAULT_MAX_PATH_LENGTH) -> None:
    """Reject paths whose string form exceeds ``max_path_length`` characters.

    Raises:
        PathSafetyError: if the path is too long.
    """
    rendered = str(path)
    if len(rendered) > max_path_length:
        raise PathSafetyError(
            f"path length {len(rendered)} exceeds limit {max_path_length}: {rendered[:120]}..."
        )


def safe_resolve(
    root: Path,
    relative: Path | str,
    *,
    allow_symlinks: bool = False,
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
    must_exist: bool = False,
) -> Path:
    """Resolve ``relative`` against ``root`` with full containment checks.

    Absolute inputs are accepted only when they already lie inside ``root``.

    Args:
        root: Project root that the result must stay within.
        relative: Path relative to the root, or an absolute path inside it.
        allow_symlinks: When false, any symlink on the path is rejected.
        max_path_length: Upper bound on the rendered path length.
        must_exist: When true, a missing target is an error.

    Returns:
        An absolute, normalised path inside ``root``.

    Raises:
        PathSafetyError: on escape, symlink, over-length, or missing target.
    """
    root_abs = root.absolute()
    raw = Path(relative)
    combined = raw if raw.is_absolute() else root_abs / raw

    # normpath collapses ".." lexically, which is what containment must be
    # judged on; resolve() would silently follow links before we can refuse them.
    normalised = Path(os.path.normpath(str(combined)))
    check_path_length(normalised, max_path_length=max_path_length)
    ensure_contained(root_abs, normalised)

    if not allow_symlinks:
        assert_no_symlink(root_abs, normalised)

    if must_exist and not normalised.exists():
        raise PathSafetyError(f"required path does not exist: {normalised}")
    return normalised


def safe_read_bytes(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> bytes:
    """Read a file, refusing anything larger than ``max_bytes``.

    The size is checked with ``stat`` before reading so an oversized file is
    never pulled into memory.

    Raises:
        PathSafetyError: if the target is missing, not a regular file, or too large.
    """
    if not path.is_file():
        raise PathSafetyError(f"not a regular file: {path}")
    size = path.stat().st_size
    if size > max_bytes:
        raise PathSafetyError(f"file size {size} exceeds limit {max_bytes}: {path}")
    data = path.read_bytes()
    if len(data) > max_bytes:  # pragma: no cover - race between stat and read
        raise PathSafetyError(f"file size {len(data)} exceeds limit {max_bytes}: {path}")
    return data


def safe_read_text(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    encoding: str = "utf-8",
) -> str:
    """Read a UTF-8 text file with a size bound and strict decoding.

    Raises:
        PathSafetyError: if the file is too large or is not valid text.
    """
    data = safe_read_bytes(path, max_bytes=max_bytes)
    try:
        return data.decode(encoding)
    except UnicodeDecodeError as exc:
        raise PathSafetyError(f"file is not valid {encoding}: {path} ({exc})") from exc


def iter_files(
    root: Path,
    directory: Path,
    patterns: Sequence[str] = ("*.yml", "*.yaml"),
    *,
    allow_symlinks: bool = False,
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
    recursive: bool = True,
) -> Iterator[Path]:
    """Yield files under ``directory`` matching ``patterns``, in deterministic order.

    Entries failing a safety check are skipped rather than raising, so a single
    stray symlink cannot abort a whole catalog scan. Ordering is sorted to keep
    reports reproducible.
    """
    if not directory.is_dir():
        return
    collected: set[Path] = set()
    for pattern in patterns:
        glob_pattern = f"**/{pattern}" if recursive else pattern
        for match in directory.glob(glob_pattern):
            if not match.is_file():
                continue
            try:
                resolved = safe_resolve(
                    root,
                    match,
                    allow_symlinks=allow_symlinks,
                    max_path_length=max_path_length,
                )
            except PathSafetyError:
                continue
            collected.add(resolved)
    yield from sorted(collected)


def relative_display(root: Path, path: Path) -> str:
    """Render ``path`` relative to ``root`` with forward slashes, for stable reports."""
    try:
        relative = path.absolute().relative_to(root.absolute())
    except ValueError:
        return path.as_posix()
    return relative.as_posix()


def ensure_directory(
    root: Path,
    directory: Path | str,
    *,
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
) -> Path:
    """Create ``directory`` inside ``root`` if needed and return its absolute path.

    Raises:
        PathSafetyError: if the directory would fall outside the root.
    """
    target = safe_resolve(root, directory, max_path_length=max_path_length)
    target.mkdir(parents=True, exist_ok=True)
    return target


def write_text(
    root: Path,
    destination: Path | str,
    content: str,
    *,
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
    encoding: str = "utf-8",
) -> Path:
    """Write ``content`` to a contained path, creating parent directories.

    Newlines are written verbatim so generated artefacts are byte-identical
    across platforms.
    """
    target = safe_resolve(root, destination, max_path_length=max_path_length)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding=encoding, newline="\n") as handle:
        handle.write(content)
    return target


def common_root(paths: Iterable[Path]) -> Path | None:
    """Return the deepest directory containing all ``paths``, or ``None`` if empty."""
    materialised = [path.absolute() for path in paths]
    if not materialised:
        return None
    try:
        return Path(os.path.commonpath([str(path) for path in materialised]))
    except ValueError:
        return None


__all__ = [
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_PATH_LENGTH",
    "SECONDARY_ROOT_MARKERS",
    "assert_no_symlink",
    "check_path_length",
    "common_root",
    "ensure_contained",
    "ensure_directory",
    "find_project_root",
    "is_contained",
    "iter_files",
    "relative_display",
    "safe_read_bytes",
    "safe_read_text",
    "safe_resolve",
    "write_text",
]
