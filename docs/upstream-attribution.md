# Upstream attribution

> **This project is independent of SigmaHQ and MITRE.** No certification, endorsement,
> affiliation, or official status is claimed or implied.

See also [`NOTICE.md`](../NOTICE.md).

## Pinned versions

Verified on **2026-08-07** and recorded in `config/upstream-versions.json`. Reported by
`sigma-detection-lab version`.

| Component | Version | Identifier |
|---|---|---|
| Sigma Rules Specification | **2.1.0** (2025-08-02) | tag `v2.1.0`, commit `0c857d07da0e71eaaab2d667b3cce6f2c8469578` |
| Sigma Correlation Specification | 2.1.0 | Documented subset only |
| pySigma | **1.5.0** | `pysigma==1.5.0` |
| pySigma Splunk backend | **2.1.0** | `pysigma-backend-splunk==2.1.0`, dialect `spl` |
| pySigma Elasticsearch backend | **2.1.0** | `pysigma-backend-elasticsearch==2.1.0`, dialect `lucene` |
| sigma-cli | 3.1.0 | Recorded for awareness; **not used** by this project |
| MITRE ATT&CK Enterprise | **19.1** | STIX release `ATT&CK-v19.1`, dataset 2026-04-28 |
| ATT&CK Navigator layer format | **4.5** | Navigator 4.9.0 minimum, 5.1.0 documented |
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-python` | v7.0.0 | `5fda3b95a4ea91299a34e894583c3862153e4b97` |

## Sigma

The Sigma detection rule format and specification are maintained by the SigmaHQ
community. This repository uses the official specification, pinned by tag and commit, and
the pySigma ecosystem for parsing and offline conversion demonstrations.

Sigma and SigmaHQ names and logos are trademarks or property of their respective owners.
**This project does not claim official SigmaHQ certification, endorsement, or
community-rule status.**

### Rules are original

All 56 rules in this repository are **original work authored for this project**. They are
not copies, derivatives, or reformattings of SigmaHQ community rules.

The originality claim is supported structurally:

- Every rule targets the synthetic environment, with paths under `C:\Synthetic\` and hosts
  from a fixed synthetic vocabulary. A community rule would reference real paths.
- Every UUID is derived from this repository's URL namespace via `uuid5`, so no upstream
  rule identifier can appear by coincidence.
- Every rule carries `author: 'Salvatore Mazzaglia'` and `license: MIT`.
- Every rule has a bespoke sidecar with a detection hypothesis, telemetry analysis, and
  tuning guidance written for it.
- Filenames follow this project's convention, not SigmaHQ's.

Verification of this claim is part of the release audit; see
[security-audit-v1.0.0](security-audit-v1.0.0.md).

### pySigma and backends

Conversion demonstrations use official SigmaHQ packages, unmodified:

- `pysigma`
- `pysigma-backend-splunk`
- `pysigma-backend-elasticsearch`

Those packages retain their upstream licenses, typically in the LGPL family. See the
installed package metadata and the upstream repositories for exact terms. They are runtime
dependencies, not vendored code; no upstream source is copied into this repository.

`sigma-cli` 3.1.0 is recorded in the pins for upstream awareness only. This laboratory
uses the local package API rather than shelling out to `sigma-cli`.

## MITRE ATT&CK

**ATT&CK® is a registered trademark of The MITRE Corporation.**

This project vendors a minimal subset of ATT&CK Enterprise identifiers and names under
`data/attack/` for offline validation of analytical metadata. Inclusion of ATT&CK
identifiers **does not imply MITRE certification, endorsement, or complete coverage.**

### Subset policy

> Only objects referenced by this project are vendored, plus the parent tactics required
> to interpret them.

The subset is deliberately partial. Vendoring the whole framework would add objects the
catalog does not use and would obscure which identifiers were deliberately chosen.

### Defensive object policy

> Detection Strategy, Analytic, and Data Component identifiers are recorded only when they
> were present in the pinned extraction. Official object names are vendored only where the
> extraction supplied them; otherwise the name field is null and no name is invented.

### Legacy Data Sources

Legacy ATT&CK Data Sources are deprecated in the current defensive model. This project
prefers Detection Strategies, Analytics, and Data Components where verified against the
pinned dataset, and does not use Data Sources as a primary mapping anywhere.

### Remapped identifiers in 19.1

| Behaviour | Identifier used | Supersedes |
|---|---|---|
| Clearing Windows event logs | `T1685.005` | `T1070.001` |
| Clearing Linux or macOS system logs | `T1685.006` | — |
| Defensive tool impairment | `T1685` | — |
| Host firewall modification | `T1686` | — |

Recorded in `data/attack/version.json`.

## ATT&CK Navigator

Layer files follow the published layer format specification, version 4.5. **This project
does not claim official Navigator endorsement.** Layers include only techniques verified
against the vendored subset, and scores reflect rule count rather than detection
confidence.

## GitHub Actions

Pinned to full commit SHAs rather than tags, because a tag can be moved and a SHA cannot:

```yaml
uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
```

Workflow permissions are restricted to `contents: read`.

## Other dependencies

| Package | Constraint | Use |
|---|---|---|
| `PyYAML` | `>=6.0,<7` | Imported directly by the hardened loader, so declared explicitly rather than relied upon transitively through pySigma |
| `jsonschema` | `>=4.23,<5` | Configuration, sidecar, fixture, and report schema validation |

Development-only: `pytest`, `pytest-cov`, `ruff`, `mypy`, `build`, `types-PyYAML`,
`types-jsonschema`.

## Project license

Original project code, original Sigma rules authored for this repository, synthetic
fixtures, and project documentation are licensed under the **MIT License** — see
[`LICENSE`](../LICENSE) — except where upstream package licenses apply to third-party
dependencies.

Author: **Salvatore Mazzaglia** ([`salvomazzaglia`](https://github.com/salvomazzaglia)).

## Update process

Recorded in `config/upstream-versions.json`:

1. Review official SigmaHQ specification releases and update the `sigma_specification`
   fields, including the commit.
2. Review PyPI and advisory databases for pySigma and the backend packages; pin compatible
   versions in `pyproject.toml`.
3. Review MITRE ATT&CK release notes; refresh the vendored subset and `version.json`
   **without inventing identifiers**.
4. Resolve GitHub Action tags to full commit SHAs via the official repositories before
   updating CI.
5. Bump `verification_date` and document the change in `CHANGELOG.md`.

Then run:

```bash
python scripts/validate-upstream-catalog.py
sigma-detection-lab validate --strict
```

An ATT&CK update in particular can turn a green build red, because a technique that was
active may have become deprecated or revoked. That is the intended behaviour: the mapping
needs a decision, not a silent pass.

## Related documents

[attack-mapping](attack-mapping.md) ·
[attack-detection-model](attack-detection-model.md) ·
[sigma-specification-profile](sigma-specification-profile.md) ·
[configuration](configuration.md)
