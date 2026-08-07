# Rule quality gates

Thirty-one gates decide whether the catalog passes. They are configured in
`config/quality-gates.json` and applied by `quality_gates.py`.

## The central principle: absent evidence fails

A gate is not a check that runs and reports. A gate is a **claim that must be
substantiated**. If the evidence for a gate was never produced — because a stage was
skipped, or a dependency was missing — the gate is **unproven**, and unproven fails.

This is why `--skip-tests` and `--skip-conversion` do not produce a green build. They
remove the evidence, not the requirement. Skipping work is never a route to passing.

## The gate table

### Structure

| Gate | Requirement |
|---|---|
| `safe_yaml_load` | Every rule file parsed under the hardened loader: no aliases, no duplicate keys, no custom tags, within all structural limits |
| `pysigma_parse` | pySigma parsed every rule without errors |
| `valid_filename` | Filename matches `^[a-z0-9]+(?:[_-][a-z0-9]+)*\.yml$` |
| `valid_logsource` | Product, category, and service are in `config/allowed-taxonomy.json` |
| `valid_date` | `date` and `modified` parse as `YYYY-MM-DD` |
| `valid_level` | `level` is in the Sigma severity vocabulary |

### Identity

| Gate | Requirement |
|---|---|
| `unique_uuid` | No two rules share a Sigma `id` |
| `unique_catalog_id` | No two rules resolve to the same catalog identifier |

### Authoring convention

| Gate | Requirement |
|---|---|
| `required_metadata` | Title, description, author, and license present and non-empty |
| `non_empty_references` | At least one reference |
| `non_empty_falsepositives` | At least one false positive |
| `specific_falsepositives` | None equals `Unknown`, `Legitimate activity`, or `Administrator activity` |
| `status_experimental_or_test` | Status is `experimental` or `test` |
| `block_stable_status` | No rule declares `status: stable` |

### Metadata

| Gate | Requirement |
|---|---|
| `sidecar_exists` | Every rule has exactly one sidecar bound by UUID |
| `detection_hypothesis_exists` | Sidecar states a non-empty detection hypothesis |
| `telemetry_requirements_exist` | Declared logs, channels, and fields are provided by a telemetry profile |
| `maturity_allowed` | Maturity is `experimental` or `tested-synthetic` |

### ATT&CK

| Gate | Requirement |
|---|---|
| `valid_attack_tags` | Tags follow the current taxonomy: hyphenated tactics, lowercase techniques |
| `verified_attack_technique_ids` | Every technique exists in the vendored ATT&CK 19.1 subset and is active |

### Fixtures and behaviour

| Gate | Requirement |
|---|---|
| `minimum_positive_fixtures_standard` | ≥ 2 positive cases per standard rule |
| `minimum_negative_fixtures_standard` | ≥ 3 negative cases per standard rule |
| `minimum_positive_sequences_correlation` | ≥ 2 positive sequences per correlation rule |
| `minimum_negative_sequences_correlation` | ≥ 2 negative sequences per correlation rule |
| `all_positive_must_match` | Every positive case matched |
| `all_negative_must_reject` | Every negative case did not match |
| `unsupported_not_counted_as_pass` | Every result reached a definite outcome; no `UNSUPPORTED` |

### Safety

| Gate | Requirement |
|---|---|
| `synthetic_marker_required` | Every fixture event carries `synthetic: true` |
| `no_real_data_patterns` | No routable addresses, non-example domains, or non-synthetic hostnames |
| `no_secrets` | No credential-shaped strings in rules or fixtures |

### Conversion

| Gate | Requirement |
|---|---|
| `conversion_status_recorded` | Every conversion attempt ended in a recorded status |

## Reading gate output

```
Quality gates
  State  Gate                                   Detail
  pass   all_negative_must_reject               all 170 case(s) behaved as expected
  pass   all_positive_must_match                all 113 case(s) behaved as expected
  pass   conversion_status_recorded             every attempt recorded a status (converted=103, unsupported=9)
  pass   maturity_allowed                       all 56 sidecar(s) within experimental, tested-synthetic
  pass   minimum_negative_fixtures_standard     all 50 rule(s) meet the minimum of 3
  pass   safe_yaml_load                         56 rule file(s) loaded safely
  pass   unsupported_not_counted_as_pass        every result was executed to a definite outcome
  ...
```

Three states appear: `pass`, `FAIL`, and `disabled`. The detail column always states the
evidence, not just the verdict — `all 170 case(s) behaved as expected` is checkable in a
way that `pass` alone is not.

Note that `conversion_status_recorded` passes while reporting nine unsupported
conversions. The gate requires that failures are **recorded**, not that they are absent.
Correlation conversion is a known 1.0 limitation, and hiding it would be the actual
violation.

## Configuration

```json
{
  "schema_version": "1.0.0",
  "gates": {
    "safe_yaml_load": true,
    "minimum_positive_fixtures_standard": 2,
    "minimum_negative_fixtures_standard": 3,
    "maturity_allowed": ["experimental", "tested-synthetic"]
  },
  "falsepositive_banned_exact": ["Unknown", "Legitimate activity", "Administrator activity"],
  "notes": "Quality gates apply to the main rule catalog. Malformed fixtures under fixtures/malformed are validation examples only."
}
```

Three value shapes are supported: a boolean to enable or disable, an integer threshold,
and a list of permitted values.

### Disabling gates

Setting a gate to `false` marks it `disabled` in the report. It is visible, not hidden —
somebody reading the report can see what was not checked.

Disabling is legitimate when adapting the laboratory to a different project (different
authors, a different maturity vocabulary) and illegitimate as a way to make a red build
green. If you disable a gate to ship, record why in `notes`.

## Severity and blocking

Findings carry a severity; gates carry a verdict. The mapping is deliberate: **a gate
failure blocks regardless of the severity of the finding beneath it**. A `medium`
finding on `specific_falsepositives` still fails the gate, because the gate encodes a
policy decision rather than a risk score.

`--strict` tightens the run further: any finding at all fails, not just those attached to
a failing gate. That is the setting a release branch should use.

## Interaction with exit codes

| Situation | Exit code |
|---|---|
| All gates pass, no findings | 0 |
| All gates pass, findings present, no `--strict` | 0 |
| All gates pass, findings present, `--strict` | 1 |
| Any gate fails | 1 |
| Configuration or path error | 3 |

See [exit-codes](exit-codes.md).

## Adding a gate

1. Add the key and default to `config/quality-gates.json`.
2. Implement the evaluation in `quality_gates.py`, returning a `GateResult` whose `detail`
   states the evidence.
3. Decide the unproven behaviour explicitly — what happens when the evidence is missing.
4. Add unit tests for pass, fail, and unproven.
5. Document it in this file.
6. Note it in `CHANGELOG.md`, because adding a gate can turn an existing green build red.

## Gates that were considered and rejected

| Candidate | Why not |
|---|---|
| Minimum ATT&CK techniques per rule | Encourages padding mappings to hit a number |
| Maximum rule complexity | Complexity is not the problem; unreviewability is, and that needs a human |
| Required `fields` block | Useful for triage, not universally applicable |
| Precision/recall thresholds | Cannot be computed from synthetic fixtures; see [coverage-methodology](coverage-methodology.md) |
| Minimum technique coverage percentage | Confuses authored content with environmental visibility |

Each rejection follows the same reasoning: a gate that can be satisfied without improving
the content makes the build green and the catalog worse.

## Related documents

[rule-lifecycle](rule-lifecycle.md) ·
[behavioral-testing](behavioral-testing.md) ·
[exit-codes](exit-codes.md) ·
[configuration](configuration.md) ·
[reports](reports.md)
