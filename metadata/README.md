# Rule Metadata Sidecars

Every rule in `rules/` has exactly one detection metadata sidecar in this directory, named
after its stable project catalog identifier, for example `SDEL-WIN-001.json`.

## Why sidecars exist

The Sigma rule itself stays portable and specification-compliant. Everything that is useful
for detection engineering but not part of the Sigma specification lives here: the detection
hypothesis, telemetry prerequisites, tuning guidance, ATT&CK defensive-object mappings, and
the backend conversion status.

## Catalog identifiers

| Prefix | Family | Range |
| --- | --- | --- |
| `SDEL-WIN` | Windows process, system, defense evasion, and persistence | 001 to 016 |
| `SDEL-PS` | PowerShell | 001 to 010 |
| `SDEL-ID` | Windows identity and Active Directory | 001 to 012 |
| `SDEL-LX` | Linux | 001 to 012 |
| `SDEL-COR` | Sigma correlation | 001 to 006 |

The Sigma `id` of each rule is derived deterministically with
`uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/salvomazzaglia/sigma-detection-engineering-lab/<catalog-id>")`,
so a catalog identifier and its UUID can always be re-derived from each other.

## Required fields

Each sidecar contains `schema_version`, `catalog_id`, `sigma_rule_id`, `title`,
`detection_hypothesis`, `platform`, `rule_family`, `maturity`, `required_logs`,
`required_channels`, `required_fields`, `optional_fields`, `field_semantics`,
`collection_prerequisites`, `expected_collection_gaps`, `normalization_assumptions`,
`ingestion_differences`, `retention_considerations`, `expected_volume`,
`false_positive_strategy`, `tuning_guidance`, `test_strategy`, `minimum_positive_tests`,
`minimum_negative_tests`, `attack_techniques`, `attack_tactics`,
`attack_detection_strategies`, `attack_analytics`, `attack_data_components`,
`unmapped_defensive_objects_reason`, `supported_backends`, `unsupported_backend_reasons`,
`related_rules`, `author`, `created_at`, `modified_at`, and `version`.

## Maturity

Only `experimental` and `tested-synthetic` are used. No rule in this repository claims
production maturity, and Sigma `status: stable` is blocked by the quality gates.

## ATT&CK defensive objects

Detection Strategy, Analytic, and Data Component identifiers are recorded only when they were
present in the pinned ATT&CK extraction under `data/attack/`. When no verified mapping exists,
the arrays stay empty and `unmapped_defensive_objects_reason` explains why. Identifiers are
never invented, and Sigma tags never carry defensive-object identifiers.

## Regeneration

Sidecars are generated together with the rules and fixtures by `tools/generate_all_rules.py`.
Edit the data definition in that script rather than editing generated files by hand.
