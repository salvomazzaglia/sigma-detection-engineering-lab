# Rule authoring guide

> SYNTHETIC DEMONSTRATION DATA — all example content below is generated for
> demonstration and refers to no real system.

This is the end-to-end procedure for adding a rule to the catalog so that
`sigma-detection-lab validate --strict` passes.

## Before you write anything

Answer these four questions in writing. If any answer is missing, the rule is not ready.

1. **Hypothesis.** What observable consequence does the adversary behaviour have?
2. **Telemetry.** Which log, channel, and fields carry that consequence, and what must be
   enabled to collect them?
3. **Benign causes.** What legitimate activity produces the same shape, and how would you
   tune it without gutting the rule?
4. **Negatives.** What are the three near misses that must *not* match?

## Step 1 — Claim a catalog identifier

| Prefix | Family | Current range |
|---|---|---|
| `SDEL-WIN` | Windows process, system, defense evasion, persistence | 001–016 |
| `SDEL-PS` | PowerShell | 001–010 |
| `SDEL-ID` | Windows identity and Active Directory | 001–012 |
| `SDEL-LX` | Linux | 001–012 |
| `SDEL-COR` | Sigma correlation | 001–006 |

Take the next free number in the family. Identifiers are never reused, even after a rule
is retired.

## Step 2 — Derive the Sigma UUID

UUIDs are derived, not random, so that a catalog identifier and its UUID can always be
re-computed from each other:

```python
import uuid
uuid.uuid5(
    uuid.NAMESPACE_URL,
    "https://github.com/salvomazzaglia/sigma-detection-engineering-lab/SDEL-WIN-017",
)
```

The `unique_uuid` and `unique_catalog_id` gates reject collisions.

## Step 3 — Choose the file path and name

```
rules/<family>/<subfolder>/<lowercase_snake_or_kebab_name>.yml
```

The filename must match `^[a-z0-9]+(?:[_-][a-z0-9]+)*\.yml$` and its stem becomes the
catalog identifier used for grepping. Name the file after the *behaviour*, not the
technique number: `process_launched_from_user_writable_temp_path.yml`, not
`t1204_002.yml`. Enforced by `valid_filename`.

## Step 4 — Write the Sigma rule

```yaml
title: 'Process Launched From Synthetic User-Writable Temporary Path'
id: a58d909c-bd70-51cc-8190-c6a67744b6bf
status: experimental
description: >-
    Detects a process image executing from a user-writable temporary or public directory in
    the synthetic lab environment. Staging binaries in directories that any interactive user
    can write to is a recurring pattern in delivery and post-exploitation activity, and it
    also occurs during legitimate software installation, so the rule is scored medium rather
    than high.
references:
    - 'https://attack.mitre.org/techniques/T1204/002/'
    - 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon'
author: 'Salvatore Mazzaglia'
date: 2026-08-01
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_writable_path:
        Image|startswith:
            - 'C:\Synthetic\Users\synthetic-user\AppData\Local\Temp\'
            - 'C:\Synthetic\Windows\Temp\'
            - 'C:\Synthetic\Users\Public\'
    filter_approved_installer:
        Image|endswith: '\synthetic_patch_installer.exe'
    condition: 'selection_writable_path and not filter_approved_installer'
falsepositives:
    - >-
        Software installers and patch bundles that unpack to the per-user temporary
        directory before executing, such as the synthetic patch installer excluded by the
        rule filter.
    - >-
        Endpoint management agents that copy remediation binaries into the Windows temporary
        directory during scheduled maintenance windows.
    - >-
        Developer build output executed directly from a temporary scratch directory on
        engineering workstations.
level: medium
license: MIT
```

### Field requirements

| Field | Requirement | Gate |
|---|---|---|
| `title` | Non-empty, describes behaviour not technique number | `required_metadata` |
| `id` | Derived UUID, unique | `unique_uuid` |
| `status` | `experimental` or `test` only; `stable` is blocked | `status_experimental_or_test`, `block_stable_status` |
| `description` | Explains the behaviour *and* the severity choice | `required_metadata` |
| `references` | At least one; ATT&CK plus vendor documentation is the norm | `non_empty_references` |
| `author` | Must be a configured required author | `required_metadata` |
| `date` | `YYYY-MM-DD`, parseable | `valid_date` |
| `tags` | Tactic tags hyphenated (`attack.defense-evasion`), techniques lowercase (`attack.t1059.001`) | `valid_attack_tags`, `verified_attack_technique_ids` |
| `logsource` | Product, category, or service from `config/allowed-taxonomy.json` | `valid_logsource` |
| `detection` | Named selections; see below | `pysigma_parse`, `safe_yaml_load` |
| `falsepositives` | At least three, all specific | `non_empty_falsepositives`, `specific_falsepositives` |
| `level` | From the Sigma vocabulary | `valid_level` |
| `license` | `MIT` | `required_metadata` |

### Detection block conventions

- **Name your selections.** `selection_writable_path`, `filter_approved_installer`. The
  taxonomy discourages `1 of them` and `all of them` in the main catalog because explicit
  names keep conditions readable and keep the deterministic matcher in scope.
- **Prefix consistently** so `1 of selection_*` remains available when you genuinely need
  it.
- **Stay inside the modifier subset:** `contains`, `startswith`, `endswith`, `re`,
  `cidr`, `exists`, `all`, `cased`. Anything else is reported `UNSUPPORTED`, which fails.
- **Keep regex short and anchored.** The limit is 256 characters and
  catastrophic-backtracking patterns are rejected.
- **Use synthetic paths.** `C:\Synthetic\...`, `/tmp/synthetic-example`, hosts from the
  approved vocabulary. The `no_real_data_patterns` gate flags anything else.

### Writing false positives that pass review

The banned exact strings are `Unknown`, `Legitimate activity`, and `Administrator
activity`. A usable false positive names three things: **who** does it, **why**, and
**what it looks like**.

> Endpoint management agents that copy remediation binaries into the Windows temporary
> directory during scheduled maintenance windows.

That sentence tells an analyst what to check and tells an engineer what to exclude.
Compare "Administrator activity", which tells nobody anything.

## Step 5 — Write the sidecar

Create `metadata/rules/SDEL-WIN-017.json`. Required keys:

```
schema_version, catalog_id, sigma_rule_id, title, detection_hypothesis, platform,
rule_family, maturity, required_logs, required_channels, required_fields,
optional_fields, field_semantics, collection_prerequisites, expected_collection_gaps,
normalization_assumptions, ingestion_differences, retention_considerations,
expected_volume, false_positive_strategy, tuning_guidance, test_strategy,
minimum_positive_tests, minimum_negative_tests, attack_techniques, attack_tactics,
attack_detection_strategies, attack_analytics, attack_data_components,
unmapped_defensive_objects_reason, supported_backends, unsupported_backend_reasons,
related_rules, author, created_at, modified_at, version
```

Validated against `schemas/metadata.schema.json`.

Three sidecar fields carry most of the review weight:

**`detection_hypothesis`** — one sentence, falsifiable, in the form "If *X*, then the
telemetry will show *Y* rather than *Z*."

**`tuning_guidance`** — must preserve detection value. Name the safe exclusion shape and
name the unsafe one explicitly.

**`unmapped_defensive_objects_reason`** — required whenever
`attack_detection_strategies`, `attack_analytics`, or `attack_data_components` is empty.
State that the identifier was absent from the pinned extraction. Never invent one.

### Telemetry fields must match the catalog

Everything in `required_logs`, `required_channels`, and `required_fields` must be
provided by a profile in `config/telemetry-catalog.json`. If your rule needs a source the
catalog does not describe, add the profile first — including its prerequisites, gaps,
normalization assumptions, ingestion differences, and retention notes.

## Step 6 — Write fixtures

```
fixtures/rules/SDEL-WIN-017/
├── manifest.json
├── positive/case_01_<what_it_shows>.jsonl
└── negative/case_01_<what_it_breaks>.jsonl
```

Minimums: **two positive, three negative** for standard rules; **two positive, two
negative sequences** for correlation rules.

One event per line:

```json
{"schema_version": "1.0.0", "event_id": "SDEL-WIN-017-POS-01", "timestamp_utc": "2026-08-01T09:01:00Z", "synthetic": true, "platform": "windows", "logsource": {"category": "process_creation", "product": "windows"}, "channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon", "host": "SYNTHETIC-HOST-01", "user": "SYNTHETIC-HOST-01\\synthetic-user", "fields": {"Computer": "SYNTHETIC-HOST-01", "EventID": 1, "Image": "C:\\Synthetic\\Users\\synthetic-user\\AppData\\Local\\Temp\\synthetic_tool.exe"}, "scenario": "Binary executed from the per-user temporary directory.", "notes": "Image prefix matches the per-user temporary directory selection."}
```

The manifest names each case, its expected outcome, its scenario, and the *rationale* —
which is the sentence a reviewer reads to understand why the case exists:

```json
{
  "name": "temp_named_subdirectory_elsewhere",
  "file": "negative/case_04_temp_named_subdirectory_elsewhere.jsonl",
  "expected": "no_match",
  "scenario": "Binary executed from a managed directory that merely contains the word Temp.",
  "rationale": "The selection uses startswith, so a similarly named managed path is excluded."
}
```

### Negative case design

Each negative breaks **exactly one** requirement. Write them by walking the condition and
disabling one clause at a time. If two negatives break the same clause, one of them is
not earning its place; if a clause has no negative, a regression there will ship
silently.

See [synthetic-event-model](synthetic-event-model.md) for the full event schema and the
permitted placeholder vocabulary.

## Step 7 — Verify locally

```bash
sigma-detection-lab explain SDEL-WIN-017          # parsed condition + per-case verdicts
sigma-detection-lab test --rule SDEL-WIN-017      # behavioral run for one rule
sigma-detection-lab validate --strict             # the full verdict, all 31 gates
sigma-detection-lab convert --rule SDEL-WIN-017 --backend splunk
```

`explain` is the fastest feedback loop: it prints the parsed condition and a per-case
table showing verdict, actual result, and *why*, so a mismatch is diagnosable without
reading matcher source.

## Common review failures

| Symptom | Cause | Fix |
|---|---|---|
| `SDEL-LOAD-001` | Duplicate YAML key, alias, or a structural limit exceeded | See [troubleshooting](troubleshooting.md) |
| `UNSUPPORTED` test result | A modifier or condition operator outside the subset | Rewrite within the subset, or extend the evaluator profile deliberately |
| `verified_attack_technique_ids` fails | Technique absent from the vendored ATT&CK subset | Add the object to `data/attack/` from the pinned extraction — never invent it |
| `specific_falsepositives` fails | A banned placeholder string | Write a concrete scenario |
| `telemetry_requirements_exist` fails | A field no declared source provides | Fix the sidecar or add a telemetry profile |
| Negative case matches | The rule is broader than intended | Usually `contains` where `startswith` was meant |

## Retiring a rule

Move the rule out of the main catalog into the retired area and set its status to
`deprecated` or `unsupported`. Those statuses are permitted only outside the main
catalog. Set sidecar `maturity` to `deprecated`, record the reason and the replacement in
`related_rules`, and keep the fixtures so the historical behaviour stays documented. The
catalog identifier is never reused.

See [rule-lifecycle](rule-lifecycle.md).

## Related documents

[detection-philosophy](detection-philosophy.md) ·
[sigma-condition-subset](sigma-condition-subset.md) ·
[synthetic-event-model](synthetic-event-model.md) ·
[logsource-and-telemetry](logsource-and-telemetry.md) ·
[rule-quality-gates](rule-quality-gates.md) ·
[false-positive-engineering](false-positive-engineering.md)
