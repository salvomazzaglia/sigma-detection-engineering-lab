"""Tests for path containment, size bounds, and project root discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from sigma_detection_engineering_lab.errors import PathSafetyError
from sigma_detection_engineering_lab.paths import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_PATH_LENGTH,
    SECONDARY_ROOT_MARKERS,
    assert_no_symlink,
    check_path_length,
    common_root,
    ensure_contained,
    ensure_directory,
    find_project_root,
    is_contained,
    iter_files,
    relative_display,
    safe_read_bytes,
    safe_read_text,
    safe_resolve,
    write_text,
)


def can_symlink(tmp_path: Path) -> bool:
    """Return whether this process may create symlinks (often false on Windows)."""
    target = tmp_path / "_symlink_probe_target"
    link = tmp_path / "_symlink_probe_link"
    target.write_text("x", encoding="utf-8")
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        return False
    link.unlink()
    return True


class TestContainment:
    def test_child_is_contained(self, tmp_path: Path) -> None:
        assert is_contained(tmp_path, tmp_path / "a" / "b") is True

    def test_root_itself_is_contained(self, tmp_path: Path) -> None:
        assert is_contained(tmp_path, tmp_path) is True

    def test_sibling_is_not_contained(self, tmp_path: Path) -> None:
        assert is_contained(tmp_path / "a", tmp_path / "b") is False

    def test_parent_is_not_contained(self, tmp_path: Path) -> None:
        assert is_contained(tmp_path / "a", tmp_path) is False

    def test_ensure_contained_returns_the_path(self, tmp_path: Path) -> None:
        candidate = tmp_path / "a"
        assert ensure_contained(tmp_path, candidate) == candidate

    def test_ensure_contained_raises_on_escape(self, tmp_path: Path) -> None:
        with pytest.raises(PathSafetyError, match="escapes project root"):
            ensure_contained(tmp_path / "a", tmp_path / "b")


class TestCheckPathLength:
    def test_short_path_is_accepted(self, tmp_path: Path) -> None:
        assert check_path_length(tmp_path) is None

    def test_over_length_path_is_refused(self) -> None:
        with pytest.raises(PathSafetyError, match="path length"):
            check_path_length(Path("a" * 100), max_path_length=50)

    def test_limit_is_inclusive(self) -> None:
        assert check_path_length(Path("a" * 50), max_path_length=50) is None

    def test_default_limit_is_reasonable(self) -> None:
        assert DEFAULT_MAX_PATH_LENGTH == 4096


class TestSafeResolve:
    def test_relative_path_is_joined_to_the_root(self, tmp_path: Path) -> None:
        assert safe_resolve(tmp_path, "rules/x.yml") == tmp_path / "rules" / "x.yml"

    def test_result_is_absolute(self, tmp_path: Path) -> None:
        assert safe_resolve(tmp_path, "a").is_absolute()

    def test_absolute_path_inside_the_root_is_accepted(self, tmp_path: Path) -> None:
        target = tmp_path / "rules" / "x.yml"
        assert safe_resolve(tmp_path, target) == target

    def test_absolute_path_outside_the_root_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(PathSafetyError, match="escapes project root"):
            safe_resolve(tmp_path / "project", tmp_path / "elsewhere" / "x.yml")

    def test_parent_traversal_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(PathSafetyError, match="escapes project root"):
            safe_resolve(tmp_path / "project", "../secret.txt")

    def test_deep_traversal_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(PathSafetyError):
            safe_resolve(tmp_path / "project", "rules/../../../etc/passwd")

    def test_interior_traversal_that_stays_inside_is_allowed(self, tmp_path: Path) -> None:
        assert safe_resolve(tmp_path, "rules/../metadata/x.json").name == "x.json"

    def test_dot_segments_are_normalised(self, tmp_path: Path) -> None:
        assert safe_resolve(tmp_path, "./rules/./x.yml") == tmp_path / "rules" / "x.yml"

    def test_over_length_path_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(PathSafetyError, match="path length"):
            safe_resolve(tmp_path, "a" * 200, max_path_length=64)

    def test_must_exist_raises_for_a_missing_target(self, tmp_path: Path) -> None:
        with pytest.raises(PathSafetyError, match="does not exist"):
            safe_resolve(tmp_path, "missing.yml", must_exist=True)

    def test_must_exist_passes_for_a_present_target(self, tmp_path: Path) -> None:
        (tmp_path / "present.yml").write_text("x", encoding="utf-8")
        assert safe_resolve(tmp_path, "present.yml", must_exist=True).is_file()

    def test_missing_target_is_fine_without_must_exist(self, tmp_path: Path) -> None:
        assert safe_resolve(tmp_path, "missing.yml").name == "missing.yml"

    def test_symlink_is_refused(self, tmp_path: Path) -> None:
        if not can_symlink(tmp_path):
            pytest.skip("this environment does not permit symlink creation")
        target = tmp_path / "real.yml"
        target.write_text("x", encoding="utf-8")
        link = tmp_path / "link.yml"
        link.symlink_to(target)
        with pytest.raises(PathSafetyError, match="symbolic links are rejected"):
            safe_resolve(tmp_path, "link.yml")

    def test_symlink_can_be_permitted_explicitly(self, tmp_path: Path) -> None:
        if not can_symlink(tmp_path):
            pytest.skip("this environment does not permit symlink creation")
        target = tmp_path / "real.yml"
        target.write_text("x", encoding="utf-8")
        (tmp_path / "link.yml").symlink_to(target)
        assert safe_resolve(tmp_path, "link.yml", allow_symlinks=True).name == "link.yml"

    def test_symlinked_parent_directory_is_refused(self, tmp_path: Path) -> None:
        if not can_symlink(tmp_path):
            pytest.skip("this environment does not permit symlink creation")
        real = tmp_path / "real_dir"
        real.mkdir()
        (tmp_path / "link_dir").symlink_to(real, target_is_directory=True)
        with pytest.raises(PathSafetyError, match="symbolic links are rejected"):
            safe_resolve(tmp_path, "link_dir/file.yml")


class TestAssertNoSymlink:
    def test_plain_path_passes(self, tmp_path: Path) -> None:
        assert assert_no_symlink(tmp_path, tmp_path / "a" / "b") is None

    def test_symlink_target_is_refused(self, tmp_path: Path) -> None:
        if not can_symlink(tmp_path):
            pytest.skip("this environment does not permit symlink creation")
        (tmp_path / "real").write_text("x", encoding="utf-8")
        (tmp_path / "link").symlink_to(tmp_path / "real")
        with pytest.raises(PathSafetyError):
            assert_no_symlink(tmp_path, tmp_path / "link")

    def test_walk_stops_at_the_root(self, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b" / "c"
        assert assert_no_symlink(tmp_path, nested) is None


class TestSafeReadBytes:
    def test_reads_file_content(self, tmp_path: Path) -> None:
        path = tmp_path / "f.txt"
        path.write_bytes(b"hello")
        assert safe_read_bytes(path) == b"hello"

    def test_missing_file_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(PathSafetyError, match="not a regular file"):
            safe_read_bytes(tmp_path / "missing.txt")

    def test_directory_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(PathSafetyError, match="not a regular file"):
            safe_read_bytes(tmp_path)

    def test_oversized_file_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "big.bin"
        path.write_bytes(b"x" * 200)
        with pytest.raises(PathSafetyError, match="exceeds limit"):
            safe_read_bytes(path, max_bytes=100)

    def test_file_at_exactly_the_limit_is_accepted(self, tmp_path: Path) -> None:
        path = tmp_path / "exact.bin"
        path.write_bytes(b"x" * 100)
        assert len(safe_read_bytes(path, max_bytes=100)) == 100

    def test_empty_file_is_accepted(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.bin"
        path.write_bytes(b"")
        assert safe_read_bytes(path) == b""

    def test_default_limit_is_one_megabyte(self) -> None:
        assert DEFAULT_MAX_FILE_BYTES == 1_048_576


class TestSafeReadText:
    def test_reads_utf8(self, tmp_path: Path) -> None:
        path = tmp_path / "f.txt"
        path.write_text("caffè", encoding="utf-8")
        assert safe_read_text(path) == "caffè"

    def test_invalid_utf8_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "f.bin"
        path.write_bytes(b"\xff\xfe\x00broken")
        with pytest.raises(PathSafetyError, match="not valid utf-8"):
            safe_read_text(path)

    def test_size_limit_applies(self, tmp_path: Path) -> None:
        path = tmp_path / "f.txt"
        path.write_text("x" * 200, encoding="utf-8")
        with pytest.raises(PathSafetyError, match="exceeds limit"):
            safe_read_text(path, max_bytes=100)

    def test_newlines_are_preserved(self, tmp_path: Path) -> None:
        path = tmp_path / "f.txt"
        path.write_bytes(b"a\nb\n")
        assert safe_read_text(path) == "a\nb\n"


class TestIterFiles:
    def build_tree(self, tmp_path: Path) -> Path:
        (tmp_path / "rules" / "windows").mkdir(parents=True)
        (tmp_path / "rules" / "a.yml").write_text("a: 1\n", encoding="utf-8")
        (tmp_path / "rules" / "b.yaml").write_text("b: 1\n", encoding="utf-8")
        (tmp_path / "rules" / "notes.md").write_text("x", encoding="utf-8")
        (tmp_path / "rules" / "windows" / "c.yml").write_text("c: 1\n", encoding="utf-8")
        return tmp_path / "rules"

    def test_finds_matching_files_recursively(self, tmp_path: Path) -> None:
        directory = self.build_tree(tmp_path)
        found = list(iter_files(tmp_path, directory))
        assert {path.name for path in found} == {"a.yml", "b.yaml", "c.yml"}

    def test_non_matching_extensions_are_skipped(self, tmp_path: Path) -> None:
        directory = self.build_tree(tmp_path)
        assert all(path.suffix != ".md" for path in iter_files(tmp_path, directory))

    def test_results_are_sorted(self, tmp_path: Path) -> None:
        directory = self.build_tree(tmp_path)
        found = list(iter_files(tmp_path, directory))
        assert found == sorted(found)

    def test_results_are_deduplicated_across_patterns(self, tmp_path: Path) -> None:
        directory = self.build_tree(tmp_path)
        found = list(iter_files(tmp_path, directory, ("*.yml", "*.yml")))
        assert len(found) == len(set(found))

    def test_non_recursive_mode_stays_at_the_top_level(self, tmp_path: Path) -> None:
        directory = self.build_tree(tmp_path)
        found = list(iter_files(tmp_path, directory, recursive=False))
        assert {path.name for path in found} == {"a.yml", "b.yaml"}

    def test_missing_directory_yields_nothing(self, tmp_path: Path) -> None:
        assert list(iter_files(tmp_path, tmp_path / "absent")) == []

    def test_custom_patterns_are_honoured(self, tmp_path: Path) -> None:
        directory = self.build_tree(tmp_path)
        found = list(iter_files(tmp_path, directory, ("*.md",)))
        assert [path.name for path in found] == ["notes.md"]

    def test_unsafe_entries_are_skipped_not_raised(self, tmp_path: Path) -> None:
        directory = self.build_tree(tmp_path)
        if not can_symlink(tmp_path):
            pytest.skip("this environment does not permit symlink creation")
        (directory / "link.yml").symlink_to(directory / "a.yml")
        found = list(iter_files(tmp_path, directory))
        assert "link.yml" not in {path.name for path in found}


class TestRelativeDisplay:
    def test_renders_a_contained_path_with_forward_slashes(self, tmp_path: Path) -> None:
        target = tmp_path / "rules" / "windows" / "x.yml"
        assert relative_display(tmp_path, target) == "rules/windows/x.yml"

    def test_falls_back_to_the_full_path_when_outside(self, tmp_path: Path) -> None:
        rendered = relative_display(tmp_path / "project", tmp_path / "other" / "x.yml")
        assert rendered.endswith("other/x.yml")

    def test_root_itself_renders_as_dot(self, tmp_path: Path) -> None:
        assert relative_display(tmp_path, tmp_path) == "."


class TestEnsureDirectory:
    def test_creates_the_directory(self, tmp_path: Path) -> None:
        created = ensure_directory(tmp_path, "temp/reports")
        assert created.is_dir()

    def test_is_idempotent(self, tmp_path: Path) -> None:
        ensure_directory(tmp_path, "temp")
        assert ensure_directory(tmp_path, "temp").is_dir()

    def test_escape_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(PathSafetyError):
            ensure_directory(tmp_path / "project", "../outside")


class TestWriteText:
    def test_writes_content(self, tmp_path: Path) -> None:
        target = write_text(tmp_path, "temp/out.txt", "hello")
        assert target.read_text(encoding="utf-8") == "hello"

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        target = write_text(tmp_path, "a/b/c/out.txt", "x")
        assert target.parent.is_dir()

    def test_newlines_are_written_verbatim(self, tmp_path: Path) -> None:
        target = write_text(tmp_path, "out.txt", "a\nb\n")
        assert target.read_bytes() == b"a\nb\n"

    def test_existing_file_is_overwritten(self, tmp_path: Path) -> None:
        write_text(tmp_path, "out.txt", "first")
        target = write_text(tmp_path, "out.txt", "second")
        assert target.read_text(encoding="utf-8") == "second"

    def test_escape_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(PathSafetyError):
            write_text(tmp_path / "project", "../escape.txt", "x")

    def test_unicode_round_trips(self, tmp_path: Path) -> None:
        target = write_text(tmp_path, "out.txt", "caffè")
        assert target.read_text(encoding="utf-8") == "caffè"


class TestCommonRoot:
    def test_returns_the_shared_parent(self, tmp_path: Path) -> None:
        paths = [tmp_path / "a" / "x", tmp_path / "a" / "y"]
        assert common_root(paths) == (tmp_path / "a").absolute()

    def test_empty_input_returns_none(self) -> None:
        assert common_root([]) is None

    def test_single_path_returns_itself(self, tmp_path: Path) -> None:
        assert common_root([tmp_path / "a"]) == (tmp_path / "a").absolute()

    def test_divergent_paths_share_the_root(self, tmp_path: Path) -> None:
        assert common_root([tmp_path / "a", tmp_path / "b"]) == tmp_path.absolute()


class TestFindProjectRoot:
    def make_root(self, base: Path) -> Path:
        base.mkdir(parents=True, exist_ok=True)
        (base / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        (base / "VERSION").write_text("1.0.0\n", encoding="utf-8")
        (base / "config").mkdir(exist_ok=True)
        return base

    def test_finds_the_root_from_itself(self, tmp_path: Path) -> None:
        root = self.make_root(tmp_path / "project")
        assert find_project_root(root) == root.resolve()

    def test_finds_the_root_from_a_descendant(self, tmp_path: Path) -> None:
        root = self.make_root(tmp_path / "project")
        nested = root / "rules" / "windows"
        nested.mkdir(parents=True)
        assert find_project_root(nested) == root.resolve()

    def test_accepts_a_file_as_the_starting_point(self, tmp_path: Path) -> None:
        root = self.make_root(tmp_path / "project")
        target = root / "rules" / "x.yml"
        target.parent.mkdir(parents=True)
        target.write_text("a: 1\n", encoding="utf-8")
        assert find_project_root(target) == root.resolve()

    def test_custom_marker_is_honoured(self, tmp_path: Path) -> None:
        root = tmp_path / "project"
        root.mkdir()
        (root / "MARKER").write_text("x", encoding="utf-8")
        assert find_project_root(root, marker="MARKER") == root.resolve()

    def test_real_repository_root_is_discoverable(self, project_root: Path) -> None:
        assert find_project_root(project_root) == project_root.resolve()

    def test_secondary_markers_are_declared(self) -> None:
        assert "VERSION" in SECONDARY_ROOT_MARKERS and "config" in SECONDARY_ROOT_MARKERS

    def test_a_marker_without_secondary_markers_loses_to_a_strong_root(
        self, tmp_path: Path, project_root: Path
    ) -> None:
        # The installed package's own location is always considered, and it is a
        # strong match, so a bare marker file does not win.
        weak = tmp_path / "weak"
        weak.mkdir()
        (weak / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        assert find_project_root(weak) == project_root.resolve()

    def test_strong_match_wins_over_a_weak_ancestor(self, tmp_path: Path) -> None:
        outer = tmp_path / "outer"
        outer.mkdir()
        (outer / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        inner = self.make_root(outer / "inner")
        assert find_project_root(inner) == inner.resolve()


class TestNormalisation:
    def test_backslash_separators_resolve_on_this_platform(self, tmp_path: Path) -> None:
        resolved = safe_resolve(tmp_path, str(Path("rules") / "x.yml"))
        assert resolved.name == "x.yml"

    def test_trailing_separator_is_collapsed(self, tmp_path: Path) -> None:
        assert safe_resolve(tmp_path, "rules/") == tmp_path / "rules"

    def test_empty_relative_resolves_to_the_root(self, tmp_path: Path) -> None:
        assert safe_resolve(tmp_path, "") == tmp_path.absolute()
