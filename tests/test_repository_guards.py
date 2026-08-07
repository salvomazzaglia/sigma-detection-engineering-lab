"""Repository-level guards.

These tests read the repository itself. They exist so that the safety claims in
the README stay true as the code changes: no dynamic execution, no shells, no
network at runtime, pinned CI actions, and synthetic-only fixture data.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src" / "sigma_detection_engineering_lab"
REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
WORKFLOWS_ROOT = REPO_ROOT / ".github" / "workflows"


def package_modules() -> list[Path]:
    return sorted(p for p in PACKAGE_ROOT.rglob("*.py") if "__pycache__" not in p.parts)


def parse_module(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def imported_names(tree: ast.Module) -> Iterator[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module


def called_names(tree: ast.Module) -> Iterator[str]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            yield func.id
        elif isinstance(func, ast.Attribute):
            yield func.attr


def bare_called_names(tree: ast.Module) -> Iterator[str]:
    """Names called without a receiver, so ``re.compile`` is not confused with ``compile``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            yield node.func.id


MODULES = package_modules()
MODULE_IDS = [p.name for p in MODULES]


@pytest.fixture(scope="session")
def module_sources() -> dict[Path, str]:
    return {path: path.read_text(encoding="utf-8") for path in MODULES}


@pytest.fixture(scope="session")
def workflow_texts() -> dict[str, str]:
    return {path.name: path.read_text(encoding="utf-8") for path in WORKFLOWS_ROOT.glob("*.yml")}


@pytest.fixture(scope="session")
def pyproject() -> str:
    return (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def fixture_records() -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in (REPO_ROOT / "fixtures").rglob("*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
    return records


class TestPackageLayout:
    def test_the_package_directory_exists(self) -> None:
        assert PACKAGE_ROOT.is_dir()

    def test_modules_were_discovered(self) -> None:
        assert len(MODULES) >= 20

    def test_the_package_is_typed(self) -> None:
        assert (PACKAGE_ROOT / "py.typed").is_file()

    def test_there_is_a_module_entry_point(self) -> None:
        assert (PACKAGE_ROOT / "__main__.py").is_file()

    @pytest.mark.parametrize("path", MODULES, ids=MODULE_IDS)
    def test_every_module_parses(self, path: Path) -> None:
        assert isinstance(parse_module(path), ast.Module)

    @pytest.mark.parametrize("path", MODULES, ids=MODULE_IDS)
    def test_every_module_has_a_docstring(self, path: Path) -> None:
        assert ast.get_docstring(parse_module(path))

    @pytest.mark.parametrize("path", MODULES, ids=MODULE_IDS)
    def test_every_module_uses_future_annotations(self, path: Path) -> None:
        if path.name == "__init__.py":
            pytest.skip("the package facade re-exports only")
        tree = parse_module(path)
        futures = {
            alias.name
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module == "__future__"
            for alias in node.names
        }
        assert "annotations" in futures

    def test_no_module_is_empty(self, module_sources: dict[Path, str]) -> None:
        assert [path.name for path, text in module_sources.items() if not text.strip()] == []


class TestNoDynamicExecution:
    FORBIDDEN_CALLS = ("eval", "exec", "compile", "execfile")

    def test_no_dynamic_execution_builtins(self) -> None:
        offenders = {
            path.name: sorted(
                set(bare_called_names(parse_module(path))) & set(self.FORBIDDEN_CALLS)
            )
            for path in MODULES
        }
        assert {name: calls for name, calls in offenders.items() if calls} == {}

    def test_no_pickle_or_marshal(self) -> None:
        banned = {"pickle", "marshal", "shelve", "dill"}
        offenders = [
            path.name
            for path in MODULES
            if {n.split(".")[0] for n in imported_names(parse_module(path))} & banned
        ]
        assert offenders == []

    def test_importlib_is_confined_to_the_optional_pysigma_integration(self) -> None:
        allowed = {"conversion.py", "sigma_validation.py", "rule_loader.py"}
        offenders = [
            path.name
            for path in MODULES
            if "importlib" in {n.split(".")[0] for n in imported_names(parse_module(path))}
            and path.name not in allowed
        ]
        assert offenders == []

    def test_no_module_writes_through_globals(self, module_sources: dict[Path, str]) -> None:
        assert [path.name for path, text in module_sources.items() if "globals()[" in text] == []

    def test_yaml_is_never_loaded_unsafely(self, module_sources: dict[Path, str]) -> None:
        offenders = [
            path.name
            for path, text in module_sources.items()
            if "yaml.load(" in text or "yaml.unsafe_load" in text or "yaml.full_load" in text
        ]
        assert offenders == []

    def test_the_yaml_loader_derives_from_safeloader(self) -> None:
        text = (PACKAGE_ROOT / "yaml_loader.py").read_text(encoding="utf-8")
        assert "SafeLoader" in text


class TestNoShellUse:
    def test_no_subprocess_import(self) -> None:
        offenders = [
            path.name
            for path in MODULES
            if "subprocess" in {n.split(".")[0] for n in imported_names(parse_module(path))}
        ]
        assert offenders == []

    def test_no_os_system_or_popen(self) -> None:
        banned = {"system", "popen", "spawnl", "spawnv", "execv"}
        offenders = [
            path.name for path in MODULES if set(called_names(parse_module(path))) & banned
        ]
        assert offenders == []

    def test_shell_true_appears_nowhere_in_the_package(
        self, module_sources: dict[Path, str]
    ) -> None:
        offenders = [path.name for path, text in module_sources.items() if "shell=True" in text]
        assert offenders == []

    def test_scripts_never_use_shell_true(self) -> None:
        offenders = [
            path.name
            for path in SCRIPTS_ROOT.glob("*.py")
            if "shell=True" in path.read_text(encoding="utf-8")
        ]
        assert offenders == []


class TestNoNetwork:
    NETWORK_MODULES = frozenset(
        {
            "requests",
            "urllib3",
            "httpx",
            "aiohttp",
            "socket",
            "ftplib",
            "telnetlib",
            "smtplib",
            "http",
            "xmlrpc",
        }
    )

    def test_no_network_client_imports(self) -> None:
        offenders = {
            path.name: sorted(
                {n.split(".")[0] for n in imported_names(parse_module(path))} & self.NETWORK_MODULES
            )
            for path in MODULES
        }
        assert {name: mods for name, mods in offenders.items() if mods} == {}

    def test_urllib_is_only_used_for_parsing(self) -> None:
        offenders = [
            path.name
            for path in MODULES
            for name in imported_names(parse_module(path))
            if name.startswith("urllib") and ("request" in name or "urlopen" in name)
        ]
        assert offenders == []

    def test_no_module_calls_urlopen(self, module_sources: dict[Path, str]) -> None:
        offenders = [path.name for path, text in module_sources.items() if "urlopen(" in text]
        assert offenders == []

    def test_no_hardcoded_http_endpoints_are_fetched(self, module_sources: dict[Path, str]) -> None:
        offenders = [
            path.name
            for path, text in module_sources.items()
            if re.search(r"(get|post|fetch|download)\s*\(\s*['\"]https?://", text)
        ]
        assert offenders == []

    def test_the_html_report_embeds_no_remote_assets(self) -> None:
        text = (PACKAGE_ROOT / "html_report.py").read_text(encoding="utf-8")
        assert 'src="http' not in text
        assert 'href="http' not in text.replace('href="https://attack.mitre.org', "")


class TestNoSecretsInTree:
    TRACKED_TEXT_SUFFIXES = (".py", ".yml", ".yaml", ".json", ".md", ".toml", ".cfg")
    PATTERNS = (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    )

    def test_no_live_credential_shapes_in_the_package(
        self, module_sources: dict[Path, str]
    ) -> None:
        # redaction.py legitimately contains the detection patterns themselves.
        offenders = [
            path.name
            for path, text in module_sources.items()
            if path.name != "redaction.py" and any(p.search(text) for p in self.PATTERNS)
        ]
        assert offenders == []

    def test_no_credential_shapes_in_the_rule_tree(self) -> None:
        offenders = []
        for path in (REPO_ROOT / "rules").rglob("*.yml"):
            text = path.read_text(encoding="utf-8")
            if any(pattern.search(text) for pattern in self.PATTERNS):
                offenders.append(path.name)
        assert offenders == []

    def test_no_dotenv_file_is_committed(self) -> None:
        assert not (REPO_ROOT / ".env").exists()

    def test_gitignore_covers_generated_output(self) -> None:
        text = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        assert "temp" in text or "reports" in text


class TestWorkflowSafety:
    def test_at_least_one_workflow_exists(self, workflow_texts: dict[str, str]) -> None:
        assert workflow_texts

    def test_no_workflow_uses_pull_request_target(self, workflow_texts: dict[str, str]) -> None:
        offenders = [name for name, text in workflow_texts.items() if "pull_request_target" in text]
        assert offenders == []

    def test_every_action_is_pinned_to_a_full_sha(self, workflow_texts: dict[str, str]) -> None:
        unpinned: list[str] = []
        for name, text in workflow_texts.items():
            for match in re.finditer(r"uses:\s*([^\s#]+)", text):
                reference = match.group(1)
                if reference.startswith("./"):
                    continue
                _, _, version = reference.partition("@")
                if not re.fullmatch(r"[0-9a-f]{40}", version):
                    unpinned.append(f"{name}: {reference}")
        assert unpinned == []

    def test_every_pinned_action_carries_a_version_comment(
        self, workflow_texts: dict[str, str]
    ) -> None:
        missing: list[str] = []
        for name, text in workflow_texts.items():
            for line in text.splitlines():
                if "uses:" in line and "@" in line and "#" not in line:
                    missing.append(f"{name}: {line.strip()}")
        assert missing == []

    def test_permissions_are_declared(self, workflow_texts: dict[str, str]) -> None:
        offenders = [name for name, text in workflow_texts.items() if "permissions:" not in text]
        assert offenders == []

    def test_permissions_are_read_only_at_the_top_level(
        self, workflow_texts: dict[str, str]
    ) -> None:
        for text in workflow_texts.values():
            assert "contents: read" in text

    def test_no_workflow_writes_to_the_repository(self, workflow_texts: dict[str, str]) -> None:
        offenders = [name for name, text in workflow_texts.items() if "contents: write" in text]
        assert offenders == []

    def test_no_workflow_curls_a_remote_script(self, workflow_texts: dict[str, str]) -> None:
        offenders = [
            name
            for name, text in workflow_texts.items()
            if re.search(r"curl[^\n]*\|\s*(ba)?sh", text)
        ]
        assert offenders == []

    def test_the_ci_workflow_runs_pytest(self, workflow_texts: dict[str, str]) -> None:
        assert any("pytest" in text for text in workflow_texts.values())

    def test_the_ci_workflow_runs_strict_validation(self, workflow_texts: dict[str, str]) -> None:
        assert any("--strict" in text for text in workflow_texts.values())

    def test_the_ci_workflow_covers_both_operating_systems(
        self, workflow_texts: dict[str, str]
    ) -> None:
        combined = "".join(workflow_texts.values())
        assert "ubuntu-latest" in combined
        assert "windows-latest" in combined


class TestScripts:
    EXPECTED = (
        "run-ci.py",
        "generate-sample-reports.py",
        "generate-demo-data.py",
        "validate-upstream-catalog.py",
        "clean-generated-files.py",
        "capture-sample-report-screenshot.py",
    )

    @pytest.mark.parametrize("name", EXPECTED)
    def test_the_script_exists(self, name: str) -> None:
        assert (SCRIPTS_ROOT / name).is_file()

    @pytest.mark.parametrize("name", EXPECTED)
    def test_the_script_parses(self, name: str) -> None:
        path = SCRIPTS_ROOT / name
        assert isinstance(ast.parse(path.read_text(encoding="utf-8"), filename=name), ast.Module)

    @pytest.mark.parametrize("name", EXPECTED)
    def test_the_script_has_a_docstring(self, name: str) -> None:
        path = SCRIPTS_ROOT / name
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=name)
        assert ast.get_docstring(tree)

    @pytest.mark.parametrize("name", EXPECTED)
    def test_the_script_has_a_main_guard(self, name: str) -> None:
        text = (SCRIPTS_ROOT / name).read_text(encoding="utf-8")
        assert '__name__ == "__main__"' in text

    @pytest.mark.parametrize("name", EXPECTED)
    def test_the_script_makes_no_network_calls(self, name: str) -> None:
        tree = ast.parse((SCRIPTS_ROOT / name).read_text(encoding="utf-8"), filename=name)
        modules = {n.split(".")[0] for n in imported_names(tree)}
        assert not modules.intersection(TestNoNetwork.NETWORK_MODULES)


class TestPackagingMetadata:
    def test_the_project_declares_a_name(self, pyproject: str) -> None:
        assert 'name = "sigma-detection-engineering-lab"' in pyproject

    def test_a_console_script_is_declared(self, pyproject: str) -> None:
        assert "sigma-detection-lab" in pyproject

    def test_a_license_file_exists(self) -> None:
        assert (REPO_ROOT / "LICENSE").is_file()

    def test_a_security_policy_exists(self) -> None:
        assert (REPO_ROOT / "SECURITY.md").is_file()

    def test_a_notice_file_credits_upstream_data(self) -> None:
        assert "ATT&CK" in (REPO_ROOT / "NOTICE.md").read_text(encoding="utf-8")

    def test_the_readme_states_the_synthetic_scope(self) -> None:
        text = (REPO_ROOT / "README.md").read_text(encoding="utf-8").lower()
        assert "synthetic" in text

    def test_no_runtime_dependency_is_a_network_client(self, pyproject: str) -> None:
        block = pyproject.split("dependencies = [", 1)[1].split("]", 1)[0].lower()
        assert "requests" not in block
        assert "httpx" not in block


class TestSyntheticFixtureData:
    def test_fixtures_were_found(self, fixture_records: list[dict[str, object]]) -> None:
        assert fixture_records

    def test_no_fixture_is_marked_non_synthetic(
        self, fixture_records: list[dict[str, object]]
    ) -> None:
        assert [r for r in fixture_records if r.get("synthetic") is False] == []

    def test_no_fixture_carries_a_routable_source_address(
        self, fixture_records: list[dict[str, object]]
    ) -> None:
        offenders = [
            r
            for r in fixture_records
            if isinstance(r.get("fields"), dict)
            and isinstance(r["fields"].get("SourceIp"), str)  # type: ignore[union-attr]
            and not str(r["fields"]["SourceIp"]).startswith(  # type: ignore[index]
                ("10.", "192.168.", "172.16.", "127.", "203.0.113.", "198.51.100.", "192.0.2.")
            )
        ]
        assert offenders == []

    def test_every_fixture_record_has_an_event_id(
        self, fixture_records: list[dict[str, object]]
    ) -> None:
        assert all(r.get("event_id") for r in fixture_records)

    def test_event_ids_are_unique_within_the_repository(
        self, fixture_records: list[dict[str, object]]
    ) -> None:
        ids = [str(r["event_id"]) for r in fixture_records]
        duplicates = {value for value in ids if ids.count(value) > 1}
        assert duplicates == set()
