# Troubleshooting

Start by reading the exit code. It tells you which category of problem you have.

| Code | Category | First action |
|---|---|---|
| `1` | Content failed | Read the gate table, then the findings beneath the failing gate |
| `2` | Bad command line | Reread the command |
| `3` | Laboratory refused to run | Read stderr — configuration, path, or permissions |

See [exit-codes](exit-codes.md).

## Installation

### `No module named sigma_detection_engineering_lab`

The package is not installed in the active interpreter.

```bash
python -m pip install -e ".[dev]"
python -c "import sigma_detection_engineering_lab as m; print(m.__version__)"
```

If you have several Pythons, check which one you are using — `python --version` must be
3.11 or newer. Installing into 3.10 fails at the `requires-python` check; running from
3.10 after installing into 3.12 produces exactly this import error.

### `sigma-detection-lab: command not found`

The console script directory is not on `PATH`. Use the module form, which always works:

```bash
python -m sigma_detection_engineering_lab validate
```

### pySigma reported unavailable

```
pysigma_available: no
pysigma_error: No module named 'sigma'
```

The laboratory still runs, but `pysigma_parse` is unproven and conversion reports
`backend_unavailable`. Install the pinned dependencies:

```bash
python -m pip install "pysigma==1.5.0" "pysigma-backend-splunk==2.1.0" "pysigma-backend-elasticsearch==2.1.0"
```

Confirm with `sigma-detection-lab version --format json`.

## Exit code 3 — the laboratory refused to run

### Configuration not found

```
sigma-detection-lab: config/production.config.json does not exist
```

`--profile <name>` loads `config/<name>.config.json`. Available profiles are `default`
and `demo`.

### Project root not found

The root is discovered by walking up from the working directory looking for
`pyproject.toml`. Run from inside the repository, or pass `--root`:

```bash
sigma-detection-lab validate --root /path/to/sigma-detection-engineering-lab
```

### Refusing to read outside the project root

A path override resolved outside the root. All paths must stay inside; this is a security
control, not a configuration limitation. See [threat-model](threat-model.md).

### Symlinks are not followed

`allow_symlinks` is `false`. Replace the symlink with the real file. Do not enable
symlinks to work around this — it is a documented mitigation for symlink escape.

### Schema validation failed

```
config validation failed: 'limits' is a required property
```

Compare your file against `schemas/config.schema.json` and against
`config/default.config.json`.

## Exit code 1 — content failed

### `SDEL-LOAD-001` — rule could not be loaded

| Message contains | Cause | Fix |
|---|---|---|
| `duplicate key` | The same key appears twice in a mapping | Remove one. This is refused because PyYAML would silently keep the last, letting a rule show one condition to a reviewer and another to the parser |
| `alias` | A YAML anchor or alias | Aliases are forbidden entirely; write the value out |
| `depth` | Nesting beyond 32 | Flatten the structure |
| `nodes` | More than 5000 nodes | Split the rule |
| `scalar` | A value over 8192 characters | Shorten it; usually an over-long regex or description |
| `unknown top-level key` | A typo such as `logsouce` | Fix the spelling. Unknown keys are errors so a typo cannot produce a rule that parses but does nothing |
| `file contains N documents` | Multi-document file that is not a correlation rule | Only correlation rules may be multi-document |

### `UNSUPPORTED` test results

The rule is outside `sdel-lab-matcher-v1`. The message names the construct:

```
unsupported condition: aggregation expressions are not evaluated by sdel-lab-matcher-v1;
express the requirement as a correlation rule instead
```

Common causes: an aggregation (use a correlation rule), a numeric comparison
(`gt`/`lt`/`gte`/`lte` are not implemented), an unknown modifier, or a regex that is too
long or rejected as catastrophic.

`UNSUPPORTED` is never a pass. See [sigma-condition-subset](sigma-condition-subset.md).

### A positive case does not match

Diagnose with `explain`, in this order:

```bash
sigma-detection-lab explain SDEL-WIN-001
```

1. **Is the parsed condition what you meant?** If not, the rule is wrong even if other
   tests pass.
2. **Does the event carry the field?** Check the `fields` mapping. Absent is not empty and
   does not match.
3. **Case?** Default is insensitive, unless `cased` is applied.
4. **`startswith` versus `contains`?** A path prefix that does not match usually means the
   fixture path and the selection prefix diverge earlier than you think.
5. **Wildcard escaping?** In Windows paths, a backslash before `*` must be escaped to be
   literal.

### A negative case matches

The rule is broader than intended, which is exactly what negatives exist to catch. Read
the case's `rationale` in the manifest: it states which requirement the case breaks, and
the rule is no longer enforcing it.

The usual cause is `contains` where `startswith` was meant, or a filter selection that was
removed or renamed without updating the condition.

### `verified_attack_technique_ids` fails

```
technique T1234.567 is not present in the vendored ATT&CK catalog
```

Either the identifier is wrong, or the vendored subset does not contain it. A well-formed
identifier is not a valid one.

Check `data/attack/enterprise-attack-subset.json`. If the technique genuinely exists in
ATT&CK 19.1, add it from the official extraction and update
`config/allowed-taxonomy.json`. **Never invent an identifier to make the gate pass.**

If the technique is deprecated or revoked, remap it. `data/attack/version.json` records
the 19.1 remappings this catalog follows — for example, Windows event log clearing moved
from `T1070.001` to `T1685.005`.

### `telemetry_requirements_exist` fails

A sidecar declares a log, channel, or field that no telemetry profile provides. Either
correct the sidecar or add the profile to `config/telemetry-catalog.json` with all seven
blocks populated. See [logsource-and-telemetry](logsource-and-telemetry.md).

### `specific_falsepositives` fails

The rule uses `Unknown`, `Legitimate activity`, or `Administrator activity`. Write a
concrete scenario naming who does it, why, and what it looks like. See
[false-positive-engineering](false-positive-engineering.md).

### `no_real_data_patterns` fails

Something outside the synthetic vocabulary appears in a fixture: a routable IP, a domain
other than `example.invalid` or `synthetic.invalid`, or a hostname outside the approved
set. Replace it. The permitted vocabulary is listed in
[synthetic-event-model](synthetic-event-model.md).

### `no_secrets` fails

A credential-shaped string was detected. Even a fake key that looks real must be replaced
with a clearly synthetic placeholder — the point of the gate is that nobody has to judge
whether a given key is real.

### `sidecar_exists` fails

Sidecars bind by **UUID**, not filename. Check that `sigma_rule_id` in the sidecar exactly
matches the rule's `id`. A renamed file does not orphan a sidecar; a changed UUID does.

### Gates fail after `--skip-tests` or `--skip-conversion`

Working as designed. Skipping removes the evidence, not the requirement. Gates that judge
those stages become unproven, and unproven fails. There is no flag combination that turns
a red catalog green.

## Conversion

### `backend_unavailable`

The backend package is not installed. This is a distinct status from `unsupported`
precisely so a missing package is not mistaken for a rule the backend declined.

### `unsupported` for a correlation rule

Expected in 1.0.0. Splunk declines `temporal_ordered` (3 rules); Elasticsearch Lucene
declines correlation entirely (6 rules). The failures are reported rather than hidden, and
`conversion_status_recorded` passes because the outcomes were recorded. See
[conversion-limitations](conversion-limitations.md).

### The converted query returns nothing in my SIEM

Almost always field mapping. The query uses the rule's field names; your index uses
something else. Verify each field resolves by querying it directly before concluding the
behaviour is absent. See [splunk-conversion](splunk-conversion.md) and
[elasticsearch-conversion](elasticsearch-conversion.md).

## Platform-specific

### Mojibake or `UnicodeEncodeError` on Windows

The banners contain em dashes that a legacy console code page cannot encode. `cli.py`
reconfigures stdout and stderr to UTF-8 with `errors="replace"`, so this should not occur;
if it does in an unusual host:

```powershell
$env:PYTHONIOENCODING = "utf-8"
chcp 65001
```

### Line-ending differences in reports

All writers use `newline="\n"` explicitly. If a report shows CRLF, the file was
transformed after writing — check `.gitattributes` and your Git `core.autocrlf` setting.

### Path separators in fixtures

Fixtures use `\\` in JSON for Windows paths, which is one escaped backslash. `\\\\` in the
source produces two literal backslashes and will not match.

## Reproducibility

Two runs differing by more than `generated_at` means something non-deterministic entered
the pipeline. Check for a fixture with a generated rather than fixed timestamp, a set
being iterated without sorting, or a dependency version drift — confirm with
`sigma-detection-lab version --format json`.

## Getting more detail

```bash
sigma-detection-lab validate --limit 500              # show more findings
sigma-detection-lab validate --format json            # full structured output
sigma-detection-lab test --verbose                    # every result, not just failures
sigma-detection-lab explain <rule>                    # parsed condition and per-case verdicts
sigma-detection-lab version --format json             # environment and pins
python scripts/validate-upstream-catalog.py           # pins against vendored data
```

## Related documents

[exit-codes](exit-codes.md) ·
[rule-quality-gates](rule-quality-gates.md) ·
[behavioral-testing](behavioral-testing.md) ·
[configuration](configuration.md)
