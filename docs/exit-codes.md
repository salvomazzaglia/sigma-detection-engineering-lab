# Exit codes

Exit codes are part of the contract, because this runs in CI.

| Code | Constant | Meaning |
|---|---|---|
| `0` | `EXIT_OK` | Everything requested succeeded |
| `1` | `EXIT_FAILED` | The analysis ran and something failed: a blocking finding, a failing behavioral test, or a failing quality gate |
| `2` | `EXIT_USAGE` | The command line itself was wrong |
| `3` | `EXIT_REFUSED` | The laboratory refused to run: bad configuration, unsafe path, unreadable catalog |

## Why 1 and 3 are different

**A failing rule and a broken installation are different problems, so they never share an
exit code.**

Exit 1 means the laboratory worked correctly and the content did not meet the standard.
The right response is to fix a rule.

Exit 3 means the laboratory could not reach a verdict. The right response is to fix the
environment. A build that treats both as "failed" will send a contributor to debug a rule
when the actual problem is a malformed configuration file.

This distinction is worth wiring into CI:

```yaml
- name: Validate
  run: |
    python -m sigma_detection_engineering_lab validate --strict
    code=$?
    if [ $code -eq 3 ]; then
      echo "::error::Laboratory refused to run — configuration or environment problem"
    fi
    exit $code
```

## Exit code 0

Returned when the requested work completed and nothing failed.

Without `--strict`, non-blocking findings still allow exit 0. Findings are visible in the
report; the gates decide whether they block.

## Exit code 1

Returned by:

| Command | Condition |
|---|---|
| `validate` | Any gate failed, or `--strict` and any finding exists |
| `test` | Any result was `FAILED`, `ERROR`, or `UNSUPPORTED` |
| `explain` | The named rule does not exist |
| `compare` | `--fail-on-regression` and a regression was detected |
| `generate-demo` | Target files exist and `--force` was not given |

`coverage`, `convert`, `list-rules`, and `version` return 0 whenever they complete.
`convert` returning 0 with unsupported results is intentional: an unsupported conversion
is a **recorded outcome**, not a failure of the command. The
`conversion_status_recorded` gate is what makes it a build concern, and that runs under
`validate`.

### `--strict`

```bash
sigma-detection-lab validate            # gates decide
sigma-detection-lab validate --strict   # any finding at all fails
```

Use `--strict` on release branches and on `main`. Without it, informational findings
accumulate silently.

### Skipping does not help

`--skip-tests` and `--skip-conversion` remove the evidence, not the requirement. Gates
that judge those stages become **unproven**, and unproven fails. There is no flag
combination that turns a red catalog green.

## Exit code 2

Returned by `argparse` for an unknown command, an unknown flag, a missing required
positional, or a bad choice value — and by `main()` when no subcommand is given, after
printing help.

```bash
sigma-detection-lab validate --format xml     # invalid choice → 2
sigma-detection-lab                           # help, then 2
```

## Exit code 3

Returned when any `SdelError` escapes, plus `OSError` and `KeyboardInterrupt`. The message
goes to stderr prefixed with the tool name.

| Cause | Example message |
|---|---|
| Missing or malformed profile | `config/nonexistent.config.json does not exist` |
| Schema-invalid configuration | `config validation failed: 'paths' is a required property` |
| Path escape | `refusing to read outside the project root` |
| Symlink encountered | `symlinks are not followed` |
| Unreadable catalog | `permission denied` |
| Interrupt | `interrupted` |

Note that a *single* unreadable or malformed rule does **not** produce exit 3. It produces
an `SDEL-LOAD-001` finding, fails `safe_yaml_load`, and yields exit 1. Exit 3 is reserved
for conditions that make the whole run meaningless.

## CI patterns

**Gate a pull request**

```bash
sigma-detection-lab validate --strict --sarif-out results.sarif
```

**Separate test failures from environment failures**

```bash
sigma-detection-lab test --junit-out tests.xml || {
  code=$?
  [ $code -eq 3 ] && echo "environment problem, not a test failure"
  exit $code
}
```

**Block coverage regressions**

```bash
sigma-detection-lab validate --json-out current.json
sigma-detection-lab compare baseline.json current.json --fail-on-regression
```

**Local orchestrator**

```bash
python scripts/run-ci.py
```

Runs Ruff, mypy, pytest, `validate --strict`, coverage, both conversions, the upstream
catalog check, and a package build, printing each step's exit code and a final
`PASS`/`FAIL`.

## Interpreting a failure

1. **Exit 2** — reread the command line.
2. **Exit 3** — read stderr. It is configuration, a path, or permissions.
3. **Exit 1 from `test`** — run `sigma-detection-lab explain <rule>` to see the parsed
   condition and per-case verdicts.
4. **Exit 1 from `validate`** — read the gate table first. The failing gate names the
   category; the findings beneath it name the rules.
5. **Exit 1 from `compare`** — read the regression list. Something that used to hold no
   longer does.

See [troubleshooting](troubleshooting.md).

## Related documents

[rule-quality-gates](rule-quality-gates.md) ·
[reports](reports.md) ·
[troubleshooting](troubleshooting.md) ·
[testing](testing.md)
