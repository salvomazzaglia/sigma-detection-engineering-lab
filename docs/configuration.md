# Configuration

All configuration is JSON under `config/`, schema-validated, and loaded explicitly. There
are no environment variables, no dotfiles, and no implicit global state.

## Files

| File | Purpose | Schema |
|---|---|---|
| `default.config.json` | The default profile: paths, limits, authors, statuses | `schemas/config.schema.json` |
| `demo.config.json` | The `demo` profile used by `generate-demo` and the examples | `schemas/config.schema.json` |
| `quality-gates.json` | Which gates run and their thresholds | — |
| `allowed-taxonomy.json` | Permitted products, categories, services, levels, statuses, tags, modifiers | — |
| `evaluator-profile.json` | The documented matcher subset and regex safety settings | — |
| `telemetry-catalog.json` | Logsource profiles, channels, providers, field semantics | — |
| `conversion-backends.json` | Backend classes, dialects, demonstration banners | — |
| `upstream-versions.json` | Pinned and verified upstream versions | — |

## Profiles

```bash
sigma-detection-lab validate --profile default
sigma-detection-lab validate --profile demo
```

`--profile <name>` loads `config/<name>.config.json`. The default is `default`.

Profiles exist so a demonstration run can use different paths and a `demo_mode` flag
without editing the production profile. They are not a mechanism for relaxing gates —
gate configuration is shared.

## The main profile

```json
{
  "schema_version": "1.0.0",
  "project_name": "sigma-detection-engineering-lab",
  "paths": {
    "rules": "rules",
    "metadata": "metadata/rules",
    "fixtures": "fixtures",
    "attack_data": "data/attack",
    "examples": "examples",
    "schemas": "schemas",
    "temp_output": "temp"
  },
  "limits": { "...": "see below" },
  "authors": { "required": ["Salvatore Mazzaglia"] },
  "license": "MIT",
  "allowed_sigma_statuses": ["experimental", "test"],
  "blocked_sigma_statuses_main_catalog": ["stable"],
  "allowed_maturity": ["experimental", "tested-synthetic"],
  "synthetic_banner": "SYNTHETIC DEMONSTRATION DATA"
}
```

All paths are relative to the project root, discovered by walking up from the working
directory until `pyproject.toml` is found. Override with `--root`.

### Path overrides

```bash
sigma-detection-lab validate --rules rules/windows --metadata metadata/rules
sigma-detection-lab test --fixtures examples/fixtures
```

`--rules`, `--metadata`, and `--fixtures` override the profile for one run. Relative
values resolve against the root; absolute values are used as given and are still subject
to containment checks.

## Limits

Every limit is a safety control, not a performance tuning knob. Raising one weakens a
documented mitigation in [threat-model](threat-model.md).

| Limit | Default | Protects against |
|---|---|---|
| `max_file_bytes` | 1 048 576 | Oversized files |
| `max_yaml_depth` | 32 | Stack exhaustion |
| `max_yaml_nodes` | 5000 | Memory exhaustion |
| `max_yaml_aliases` | **0** | Billion-laughs expansion |
| `max_scalar_length` | 8192 | Oversized scalars |
| `max_mapping_size` | 512 | Oversized mappings |
| `max_sequence_length` | 512 | Oversized sequences |
| `max_path_length` | 4096 | Path-length attacks |
| `max_regex_length` | 256 | Catastrophic backtracking |
| `max_events_per_fixture` | 200 | Oversized fixtures |
| `max_correlation_sequence_events` | 100 | Oversized sequences |
| `allow_symlinks` | `false` | Symlink escape |

## Quality gates

See [rule-quality-gates](rule-quality-gates.md) for the full table. Three value shapes are
supported:

```json
{
  "gates": {
    "safe_yaml_load": true,
    "minimum_positive_fixtures_standard": 2,
    "maturity_allowed": ["experimental", "tested-synthetic"]
  },
  "falsepositive_banned_exact": ["Unknown", "Legitimate activity", "Administrator activity"]
}
```

A gate set to `false` appears as `disabled` in the report rather than being hidden.

## Taxonomy

`allowed-taxonomy.json` constrains what a rule may declare:

```json
{
  "allowed_products": ["linux", "windows"],
  "allowed_categories": ["file_event", "process_access", "process_creation", "ps_script", "registry_set", "wmi_event"],
  "allowed_services": ["auth", "security", "system"],
  "allowed_statuses": ["experimental", "test"],
  "blocked_statuses": ["stable", "deprecated", "unsupported"],
  "allowed_maturity": ["experimental", "tested-synthetic"],
  "allowed_tactic_tags": ["attack.command-and-control", "..."],
  "allowed_technique_tags": ["attack.t1003.001", "..."],
  "allowed_correlation_types": ["event_count", "value_count", "temporal", "temporal_ordered"],
  "allowed_field_modifiers": ["contains", "startswith", "endswith", "re", "cidr", "exists", "all", "cased"],
  "condition_conventions": {
    "prefer_named_selections": true,
    "avoid_in_main_catalog": ["1 of them", "all of them"]
  }
}
```

Explicit allowlists mean adding a technique tag is a deliberate two-file change (taxonomy
plus ATT&CK subset) rather than a one-line edit that nobody notices in review.

## Evaluator profile

```json
{
  "name": "sdel-lab-matcher-v1",
  "purpose": "Deterministic behavioral unit testing only. Not a SIEM backend substitute.",
  "supported_modifiers": ["contains", "startswith", "endswith", "re", "cidr", "exists", "all", "cased"],
  "supported_condition_ops": ["and", "or", "not", "parentheses", "named_selection", "1_of_prefix_star", "all_of_prefix_star"],
  "unsupported": ["unknown_modifiers", "aggregations", "backend_custom_fields", "arbitrary_expressions", "near", "gt", "gte", "lt", "lte", "expand"],
  "case_handling": {
    "default": "case_insensitive",
    "with_cased_modifier": "case_sensitive",
    "notes": "Lab semantics are explicit and may differ from vendor backends."
  },
  "regex": { "flavor": "python_re", "max_length": 256, "reject_catastrophic_patterns": true },
  "correlation_supported_types": ["event_count", "value_count", "temporal", "temporal_ordered"]
}
```

The `name` field is recorded in every behavioral test report, so a result always states
which semantics produced it.

## Conversion backends

```json
{
  "backends": {
    "splunk": {
      "enabled": true,
      "package": "pysigma-backend-splunk",
      "version": "2.1.0",
      "backend_class": "sigma.backends.splunk.SplunkBackend",
      "dialect": "spl",
      "pipeline": null,
      "network": false,
      "deployment": false
    }
  },
  "correlation_conversion": { "supported_in_v1": false }
}
```

`network: false` and `deployment: false` are assertions recorded in the output, so a
reader of a conversion record can see that no connection was made.

## Upstream versions

`upstream-versions.json` pins the Sigma specification, pySigma and its backends, ATT&CK,
the Navigator layer format, and the GitHub Actions SHAs, with a `verification_date` and a
five-step update process. Reported by `sigma-detection-lab version`. See
[upstream-attribution](upstream-attribution.md).

## Adapting the laboratory to another project

The realistic changes are:

| Change | File | Note |
|---|---|---|
| Author | `default.config.json` → `authors.required` | |
| Project name | `default.config.json` → `project_name` | Appears in reports |
| Directory layout | `default.config.json` → `paths` | Must stay inside the root |
| Logsource taxonomy | `allowed-taxonomy.json` | Add telemetry profiles too |
| Technique allowlist | `allowed-taxonomy.json` + `data/attack/` | Both, always |
| Gate thresholds | `quality-gates.json` | Record why in `notes` |

Do **not** relax `max_yaml_aliases`, `allow_symlinks`, or the regex limits. Those are
security controls, and each maps to a documented threat.

## Validating configuration

```bash
sigma-detection-lab version --format json         # resolved config and pins
python scripts/validate-upstream-catalog.py        # pins against the vendored data
sigma-detection-lab validate --strict              # everything
```

A malformed configuration produces exit code **3**, not 1: the laboratory refused to run,
which is a different problem from the catalog failing.

## Related documents

[rule-quality-gates](rule-quality-gates.md) ·
[logsource-and-telemetry](logsource-and-telemetry.md) ·
[exit-codes](exit-codes.md) ·
[threat-model](threat-model.md)
