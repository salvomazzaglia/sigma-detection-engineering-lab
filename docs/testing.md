# Testing

Two independent test layers, answering two different questions.

| Layer | Question | Tool |
|---|---|---|
| **Behavioral tests** | Do the *rules* behave as their authors claimed? | `sigma-detection-lab test` |
| **Unit tests** | Does the *laboratory* behave as documented? | `pytest` |

A green behavioral suite with a broken matcher proves nothing, so both layers are
required. This document covers the unit-test layer; see
[behavioral-testing](behavioral-testing.md) for the other.

## Running everything

```bash
python -m pip install -e ".[dev]"

python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src
python -m pytest -q
sigma-detection-lab validate --strict

# Or all of the above plus conversions and a package build
python scripts/run-ci.py
```

## pytest configuration

```toml
[tool.pytest.ini_options]
minversion = "8.0"
testpaths = ["tests"]
addopts = "-ra --strict-markers --strict-config"
filterwarnings = ["error"]
```

`filterwarnings = ["error"]` turns every warning into a failure. A `DeprecationWarning`
from a dependency is a signal that a pin needs attention, and letting it scroll past is how
that signal gets lost.

`--strict-markers` and `--strict-config` prevent a typo in a marker or a configuration key
from being silently ignored.

## What the unit tests must cover

The laboratory's own correctness claims are what the unit layer exists to defend. Each
area below corresponds to a claim made elsewhere in this documentation, and a claim
without a test is an assertion.

### Safety controls

Each limit needs a test that the limit **triggers**, not just that normal input passes.

- YAML depth, node count, alias count (must be zero), scalar length, mapping size,
  sequence length.
- Duplicate mapping keys rejected — the review-bypass case.
- Custom tags rejected.
- Path containment: `../` escape, absolute path outside the root, symlink refusal.
- File size and path length caps.
- Regex length cap and catastrophic-pattern rejection.

### Condition parser

- Every supported construct parses to the expected AST.
- Every rejected construct raises with a message naming the construct.
- Operator precedence: `a or b and c` binds as `a or (b and c)`.
- `1 of prefix*` and `all of prefix*` expand correctly.
- Malformed input — unbalanced parentheses, trailing operators — is rejected.

### Matcher semantics

Every documented interpretation choice needs a test, because an undocumented change in
behaviour would otherwise be invisible.

- Each modifier: `contains`, `startswith`, `endswith`, `re`, `cidr`, `exists`, `all`,
  `cased`.
- Case-insensitive default; case-sensitive under `cased`.
- Absent versus present-and-null.
- Implicit OR across a value list; implicit AND across selection keys.
- Wildcard translation and escaping.
- Field resolution order: `fields` key, then top-level attribute, then absent.

### Correlation engine

- All four types: `event_count`, `value_count`, `temporal`, `temporal_ordered`.
- Window boundary inclusivity — an event exactly at `timespan` is inside.
- Grouping: events missing a grouping field do not join a group.
- Ordering: interleaved unrelated events do not break order; reversed occurrences do.
- Threshold arithmetic at `N-1`, `N`, and `N+1`.
- Base-rule resolution by `name` and by `id`.

### Loaders

- Unknown top-level key is a load error.
- Multi-document files allowed only for correlation.
- Exactly one correlation document per file.
- Sidecar binding by UUID, including the orphan and duplicate cases.
- Fixture manifest parsing and directory-convention fallback.
- ATT&CK catalog: combined document, split files, missing directory yields an
  *unavailable* catalog rather than an error.

### Validation and gates

- Each validator produces the expected finding for its failure case.
- Each gate passes, fails, and is **unproven** in the right circumstances. The unproven
  path is the one most likely to regress, because it only occurs when a stage is skipped.
- `--strict` changes the exit code with non-blocking findings present.

### Redaction

- Each credential pattern is detected.
- Each real-data pattern is detected: routable address, non-example domain,
  non-synthetic hostname.
- Redaction actually replaces the secret in report output.
- No false positive on the permitted synthetic vocabulary.

### Reports

- JSON is deterministic: two renders of the same input are byte-identical apart from
  timestamps.
- SARIF carries no `security-severity` and sets `isVulnerabilityFinding: false`.
- JUnit renders `UNSUPPORTED` as `<failure>`, not `<skipped>`, and header totals agree
  with the case elements.
- CSV neutralises formula-injection prefixes.
- HTML escapes interpolated values and contains no external resource reference.
- Every banner appears verbatim in the format that requires it.

### CLI

- Each command's exit code for success, failure, usage error, and refusal.
- `--skip-tests` and `--skip-conversion` leave the dependent gates unproven, and therefore
  failing.
- Path overrides resolve against the root and remain contained.
- `generate-demo` refuses to write outside the root, and refuses to overwrite without
  `--force`.

## Test conventions

- One behaviour per test; the name states the behaviour.
- Fixtures go in `tmp_path`, never in the repository tree.
- No network, no sleeps, no reliance on wall-clock time.
- Deterministic input; no randomness without a fixed seed.
- Table-driven tests for the modifier and gate matrices.
- Per-file ruff ignores for tests are declared in `pyproject.toml`
  (`S101`, `S105`, `S106`, `PLR2004`).

## Static analysis

**Ruff** with `E, F, W, I, N, UP, B, C4, SIM, PTH, RUF, S, TID, BLE, DTZ` at line length
100. `S` is the bandit ruleset; `BLE` forbids blind `except:`; `DTZ` forbids naive
datetimes, which matters because every timestamp in this project is UTC.

Two documented ignores: `UP042`, because `str, Enum` keeps members JSON-serialisable in a
way `StrEnum` would change, and `S101`, because assertions are used in tests.

**mypy** in strict mode over `src`, with `disallow_untyped_defs`,
`disallow_any_generics`, `warn_unreachable`, and `warn_unused_ignores`. pySigma modules
are the only `ignore_missing_imports` override, because they ship partial stubs and are
optional at runtime.

The package ships `py.typed`, so downstream consumers get the annotations.

## Coverage

```bash
python -m pytest --cov --cov-report=term-missing
```

Branch coverage over `sigma_detection_engineering_lab`, with `pragma: no cover`,
`if TYPE_CHECKING:`, and `raise NotImplementedError` excluded.

Coverage is a diagnostic, not a target. High coverage of `to_dict()` methods says nothing
useful; the areas listed above are what actually need to be covered, and they need to be
covered at their **boundaries** rather than in their happy paths.

## Continuous integration

GitHub Actions on `ubuntu-latest` and `windows-latest`, Python 3.11 and 3.12, with
`fail-fast: false` so one platform's failure does not hide another's.

Windows is in the matrix specifically because of path separators, line endings, and
console encoding — `cli.py` reconfigures stdout and stderr to UTF-8 because a legacy
Windows code page cannot encode the banner characters, and that path needs exercising.

Actions are pinned to full commit SHAs, and workflow permissions are `contents: read`.

## Adding tests with a change

| Change | Required tests |
|---|---|
| New rule | Fixtures at or above the minimums; `validate --strict` green |
| New modifier or operator | Semantics tests including boundaries; profile updated |
| New gate | Pass, fail, and unproven |
| New report format | Determinism and injection safety |
| New backend | Conversion status recorded for every rule |
| Changed limit | A test proving the new limit triggers |

## Related documents

[behavioral-testing](behavioral-testing.md) ·
[exit-codes](exit-codes.md) ·
[rule-quality-gates](rule-quality-gates.md) ·
[troubleshooting](troubleshooting.md)
