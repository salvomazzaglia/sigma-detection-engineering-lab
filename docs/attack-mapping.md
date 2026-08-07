# ATT&CK mapping

> **ATT&CK® is a registered trademark of The MITRE Corporation.** This project is
> independent of MITRE. Vendoring ATT&CK identifiers implies no certification,
> endorsement, or complete coverage.

## Pinned dataset

| Item | Value |
|---|---|
| Domain | `enterprise-attack` |
| Version | **19.1** |
| STIX release | `ATT&CK-v19.1` |
| Dataset date | 2026-04-28 |
| Source | `https://github.com/mitre-attack/attack-stix-data` |
| Location | `data/attack/*.json` |

Nothing is fetched at runtime. The subset is vendored so the laboratory produces identical
results on an air-gapped machine and so mapping validation can never depend on network
availability.

## Subset policy

> Only objects referenced by this project are vendored, plus the parent tactics required
> to interpret them.

Vendoring the whole framework would add tens of megabytes of objects the catalog does not
use and would obscure which identifiers were deliberately chosen. The subset is
deliberately partial, and this document says so rather than letting a reader infer
completeness from the presence of a `data/attack/` directory.

Files:

| File | Contents |
|---|---|
| `enterprise-attack-subset.json` | Techniques and tactics |
| `detection-strategies-subset.json` | `DET####` objects |
| `analytics-subset.json` | `AN####` objects |
| `data-components-subset.json` | `DC####` objects |
| `version.json` | Version, dataset date, subset policy, remapping notes |

## The invented-identifier problem

`attack_catalog.py` states the rule directly:

> No identifier is ever accepted merely because it looks well formed: a syntactically
> valid `T9999` that ATT&CK does not define is an invented identifier and is rejected.

Shape validation is necessary and never sufficient. Both checks apply:

| Object | Pattern | Existence check |
|---|---|---|
| Technique | `^T\d{4}(?:\.\d{3})?$` | Must exist in the vendored subset |
| Tactic | `^TA\d{4}$` or a lowercase shortname | Must exist |
| Detection Strategy | `^DET\d{4}$` | Must exist |
| Analytic | `^AN\d{4}$` | Must exist |
| Data Component | `^DC\d{4}$` | Must exist |

An object that is `deprecated` or `revoked` is present but **not active**, and mapping to
it is a finding. `verified_attack_technique_ids` covers both cases.

## What is validated

`attack_mapping.py` checks:

1. Every technique in the Sigma `tags` is well-formed and exists in the vendored catalog.
2. Every technique in the sidecar's `attack_techniques` exists and is active.
3. Sigma tags and sidecar mappings **agree**. A rule tagged `attack.t1059.001` whose
   sidecar maps T1027 is inconsistent, and one of the two is wrong.
4. Tactic tags resolve, by `TA####` identifier, shortname, or hyphenated name.
5. Defensive-object identifiers, where present, exist in the pinned extraction.
6. Where defensive arrays are empty, `unmapped_defensive_objects_reason` is non-empty.

When the catalog directory is missing entirely, the loader returns an *unavailable*
catalog rather than raising. The rest of the laboratory still runs, and mapping validation
reports that identifiers could not be verified — which is a different statement from
"they are valid".

## Tag conventions

```yaml
tags:
    - attack.execution        # tactic, hyphenated where multi-word
    - attack.t1204.002        # technique, lowercase
```

- Tactic tags use the current hyphenated form: `attack.defense-evasion`,
  `attack.command-and-control`, `attack.privilege-escalation`.
- Technique tags use the lowercase identifier, restored to canonical `T1204.002` form
  internally.
- **Sigma tags never carry `DET`, `AN`, or `DC` identifiers.** Those live in the sidecar
  only, where their provenance can be stated alongside them.

`config/allowed-taxonomy.json` holds explicit allowlists of both tactic and technique
tags, so adding a mapping is a deliberate two-file change rather than a one-line edit.

## Sidecar mapping

```json
"attack_techniques": [
  { "id": "T1204.002", "name": "User Execution: Malicious File" }
],
"attack_tactics": [
  { "id": "TA0002", "name": "Execution" }
],
"attack_detection_strategies": [],
"attack_analytics": [],
"attack_data_components": [],
"unmapped_defensive_objects_reason": "No Detection Strategy, Analytic, or Data Component identifier for this technique was present in the pinned ATT&CK extraction used by this lab. Defensive arrays are left empty rather than populated with unverified identifiers. Unmapped techniques: T1204.002.",
"attack_version": "19.1"
```

The empty arrays plus the stated reason are the point. Populating them with plausible
identifiers would produce a richer-looking mapping that nobody could verify. See
[attack-detection-model](attack-detection-model.md).

## Remapped identifiers in ATT&CK 19.1

ATT&CK 19.x reorganised several defense-evasion techniques. `data/attack/version.json`
records the remappings this catalog follows:

| Behaviour | Identifier used | Superseded |
|---|---|---|
| Clearing Windows event logs | `T1685.005` | `T1070.001` |
| Clearing Linux or macOS system logs | `T1685.006` | — |
| Defensive tool impairment | `T1685` | — |
| Host firewall modification | `T1686` | — |

Rules affected: `SDEL-WIN-010`, `SDEL-WIN-011`, `SDEL-WIN-013`, `SDEL-LX-009`,
`SDEL-PS-005`, `SDEL-PS-006`, `SDEL-ID-011`.

Recording the supersession matters because a reader who knows the older identifier needs
to be able to find the rule.

## Catalog mapping in 1.0.0

**36 techniques across 6 tactics**, all 56 rules mapped.

| Tactic | Tag |
|---|---|
| Command and Control | `attack.command-and-control` |
| Credential Access | `attack.credential-access` |
| Defense Evasion | `attack.defense-evasion` |
| Execution | `attack.execution` |
| Persistence | `attack.persistence` |
| Privilege Escalation | `attack.privilege-escalation` |

Techniques include T1003.001, T1003.006, T1027, T1053.003, T1053.005, T1059.001,
T1059.003, T1059.004, T1098, T1098.004, T1105, T1110.001, T1110.003, T1112, T1136.001,
T1140, T1204.002, T1218.005, T1218.010, T1222.002, T1484.001, T1484.002, T1505.003,
T1543.002, T1543.003, T1546.003, T1547.001, T1547.006, T1548.003, T1555, T1558.003,
T1620, T1685, T1685.005, T1685.006, and T1686.

Inspect any rule's mapping with:

```bash
sigma-detection-lab explain SDEL-WIN-001
sigma-detection-lab list-rules --technique attack.t1204.002
```

## Navigator layers

```bash
sigma-detection-lab coverage --tests --navigator temp/layer.json
```

Produces an ATT&CK Navigator **layer format 4.5** document (Navigator 4.9.0 minimum,
5.1.0 documented). Two properties are enforced by `navigator.py`:

1. **Only verified techniques appear.** A technique absent from the vendored catalog is
   omitted from the layer and listed separately in the console output, so the omission is
   visible rather than silent.
2. **Scores reflect rule count, not detection confidence.** A technique with three rules
   scores higher than one with a single rule. That is a statement about how much was
   authored, not about how well it is detected.

A Navigator layer is visually persuasive, which makes the second property worth repeating
in any presentation of the layer.

## Legacy Data Sources

ATT&CK's legacy Data Sources are deprecated in the current defensive model.
`version.json` records their status as `deprecated` and their usage as *"Not used as a
primary mapping anywhere in this project."* Detection Strategies, Analytics, and Data
Components are preferred where the pinned extraction supplies them.

## Updating the dataset

1. Obtain the new STIX release from `attack-stix-data`.
2. Extract only the objects this project references, plus their parent tactics.
3. Update `data/attack/version.json`: version, dataset date, STIX release identifier, and
   any remapping notes.
4. Update `config/upstream-versions.json` and bump `verification_date`.
5. Run `python scripts/validate-upstream-catalog.py`.
6. Run `sigma-detection-lab validate --strict` and resolve any technique that has become
   deprecated or revoked.
7. Record the change in `CHANGELOG.md`.

**Never add an object that is not present in the official release.** If a rule needs an
identifier the extraction lacks, the extraction is wrong — not the framework.

## Related documents

[attack-detection-model](attack-detection-model.md) ·
[coverage-methodology](coverage-methodology.md) ·
[upstream-attribution](upstream-attribution.md) ·
[configuration](configuration.md)
