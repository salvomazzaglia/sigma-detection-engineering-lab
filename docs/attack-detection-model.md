# ATT&CK detection model

> ATT&CK® is a registered trademark of The MITRE Corporation. This project is independent
> of MITRE.

ATT&CK's defensive model has changed. This document explains what the current objects are,
how this laboratory uses them, and why most of the catalog's defensive arrays are empty.

## From Data Sources to Detection Strategies

The legacy model attached **Data Sources** and **Data Components** to techniques,
answering "what telemetry would show this?". It was coarse: "Process: Process Creation"
covers a very large amount of ground.

The current model introduces richer objects:

| Object | Prefix | Answers |
|---|---|---|
| **Detection Strategy** | `DET####` | What is the overall approach to detecting this technique? |
| **Analytic** | `AN####` | What concrete analytic implements part of that strategy? |
| **Data Component** | `DC####` | What telemetry does the analytic consume? |

`data/attack/version.json` records the consequence for this project:

> Legacy ATT&CK Data Sources are deprecated in the current defensive model. This project
> prefers Detection Strategies, Analytics, and Data Components where verified against the
> pinned ATT&CK dataset.

## Where the objects live

Defensive-object identifiers appear **only in the sidecar**, never in Sigma tags:

```json
"attack_techniques": [{ "id": "T1204.002", "name": "User Execution: Malicious File" }],
"attack_tactics": [{ "id": "TA0002", "name": "Execution" }],
"attack_detection_strategies": [],
"attack_analytics": [],
"attack_data_components": [],
"unmapped_defensive_objects_reason": "No Detection Strategy, Analytic, or Data Component identifier for this technique was present in the pinned ATT&CK extraction used by this lab. Defensive arrays are left empty rather than populated with unverified identifiers. Unmapped techniques: T1204.002."
```

Two reasons for the separation. Sigma's tag taxonomy is for tactics and techniques, and
adding a `DET` identifier there would produce a tag no other Sigma consumer understands.
And the sidecar is where provenance can be stated — the identifier plus the reason it is
or is not present.

## Why the arrays are mostly empty

This is the most likely question a reader has, so it is answered directly: **the
extraction is partial, and unverifiable identifiers are refused.**

`version.json` states the policy:

> Detection Strategy, Analytic, and Data Component identifiers are recorded only when they
> were present in the pinned extraction. Official object names are vendored only where the
> extraction supplied them; otherwise the name field is null and no name is invented.

Populating those arrays with plausible-looking identifiers would produce a mapping that
looks more complete and can be checked by nobody. An empty array with a stated reason is
strictly more useful than a fabricated one, because it tells the reader exactly what is
known and what is not.

The same logic applies to names. If the extraction supplied `DET0031` without a name, the
name stays `null`. Inventing "Suspicious Process Execution" would be a plausible guess and
an unverifiable claim.

## The unmapped reason field

`unmapped_defensive_objects_reason` is required whenever a defensive array is empty. It
must state:

1. Which defensive object types are missing.
2. Why — normally that the identifier was absent from the pinned extraction.
3. Which techniques are affected.

A reason of "N/A" or an empty string fails validation. The field exists to record a
specific fact, and a placeholder records nothing.

## How this differs from a coverage claim

A defensive-object mapping says *this rule relates to this documented detection approach*.
It does not say:

- that the rule implements the strategy completely;
- that the analytic and the rule are equivalent;
- that having the data component means the rule will fire;
- that the technique is "covered".

The distinction is the same one that runs through
[coverage-methodology](coverage-methodology.md): a mapping is a claim about the rule's
subject, not about your environment's visibility.

## Sub-techniques

Sub-techniques are mapped at the level the rule actually detects.

`SDEL-PS-001` maps `T1059.001` (PowerShell), not the parent `T1059` (Command and Scripting
Interpreter), because the rule specifically detects PowerShell. Mapping to the parent
would overstate the rule's scope; mapping to both would double-count in coverage
arithmetic.

`attack_catalog.py` exposes `parent_technique()` for callers that need to roll up to the
parent, but the stored mapping stays at the detected level.

## Multi-technique rules

A rule may map to several techniques where the behaviour genuinely spans them:

| Rule | Techniques | Why |
|---|---|---|
| `SDEL-PS-009` | T1027, T1059.001, T1140 | Obfuscation, PowerShell execution, and deobfuscation in one script block |
| `SDEL-COR-006` | T1105, T1204.002 | Transfer followed by execution |
| `SDEL-LX-007` | T1059.004, T1105 | Network retrieval piped to a shell |

The test is whether the rule's condition genuinely evidences each technique. A rule that
maps to five techniques because they are all "kind of related" inflates coverage without
improving detection, which is exactly why no gate requires a minimum technique count.

## Tactic assignment

Tactics come from the technique's own kill-chain phases in the vendored catalog rather
than being chosen by the rule author. A technique that belongs to several tactics
contributes all of them, which is why `SDEL-ID-003` (T1098, Account Manipulation) appears
under both persistence and privilege escalation.

## Working with the model

```bash
# Every rule addressing a technique
sigma-detection-lab list-rules --technique attack.t1059.001

# Full mapping for one rule, including the unmapped reason
sigma-detection-lab explain SDEL-PS-001

# Technique and tactic counts, plus techniques with no rule
sigma-detection-lab coverage

# Vendored catalog version and object counts
sigma-detection-lab version --format json
```

`coverage` also lists **techniques not present in the vendored catalog**, which are
omitted from any Navigator layer. That list should be empty; if it is not, either a
mapping is wrong or the extraction is incomplete.

## Related documents

[attack-mapping](attack-mapping.md) ·
[coverage-methodology](coverage-methodology.md) ·
[detection-philosophy](detection-philosophy.md) ·
[upstream-attribution](upstream-attribution.md)
