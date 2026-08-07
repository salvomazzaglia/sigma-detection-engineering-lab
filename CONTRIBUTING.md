# Contributing

Thank you for considering a contribution. This project holds detection content to the same
review, test, and release standards as application code, so the bar for a rule is roughly
the bar for a code change.

## Non-negotiables

These four rules have no exceptions. A pull request violating any of them will be closed
rather than revised.

1. **Rules must be original.** No copies, derivatives, or reformattings of SigmaHQ
   community rules or any other third-party content. By opening a pull request you assert
   that the content is your own work, licensed MIT.
2. **Data must be synthetic.** No real hostnames, accounts, addresses, domains, logs,
   alerts, incidents, or credentials. Not in rules, not in fixtures, not in issues, not in
   pull-request descriptions.
3. **ATT&CK identifiers must exist.** Every identifier must be present in the vendored
   ATT&CK 19.1 subset. A well-formed identifier is not a valid one. **Never invent an
   identifier to make a gate pass.**
4. **No production claims.** Nothing may claim production readiness, complete coverage,
   certification, endorsement, or that a match proves compromise.

## Getting set up

```bash
git clone https://github.com/salvomazzaglia/sigma-detection-engineering-lab.git
cd sigma-detection-engineering-lab

python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"

sigma-detection-lab validate --strict
```

Requires Python 3.11 or newer. A clean checkout must validate before you change anything;
if it does not, that is the first bug to report.

## Before you open a pull request

```bash
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src
python -m pytest -q
sigma-detection-lab validate --strict
```

Or run everything at once:

```bash
python scripts/run-ci.py
```

## Contributing a rule

Follow [`docs/rule-authoring-guide.md`](docs/rule-authoring-guide.md) in full. The
checklist:

- [ ] Detection hypothesis written **before** the rule, in one falsifiable sentence
- [ ] Next free catalog identifier in the family
- [ ] UUID derived with `uuid5(NAMESPACE_URL, "<repo-url>/<catalog-id>")`
- [ ] Filename matches `^[a-z0-9]+(?:[_-][a-z0-9]+)*\.yml$` and names the behaviour, not
      the technique number
- [ ] `status: experimental` or `test` — never `stable`
- [ ] At least one reference, `license: MIT`, author set
- [ ] Named selections; no `1 of them` in the main catalog
- [ ] Modifiers within the supported subset
- [ ] **Three specific false positives** — no `Unknown`, `Legitimate activity`, or
      `Administrator activity`
- [ ] Description justifies the chosen severity
- [ ] Complete sidecar in `metadata/rules/<catalog-id>.json`
- [ ] Telemetry requirements satisfied by a profile in `config/telemetry-catalog.json`
- [ ] Tuning guidance names the destructive exclusion and forbids it
- [ ] ≥ 2 positive and ≥ 3 negative fixtures, each negative breaking exactly one
      requirement
- [ ] `manifest.json` with `expected`, `scenario`, and `rationale` for every case
- [ ] Only the permitted synthetic vocabulary
- [ ] `sigma-detection-lab validate --strict` passes

### The two things reviewers look at first

**The detection hypothesis.** If it is not falsifiable, the rule is a search rather than a
detection. "Detects suspicious PowerShell" is not a hypothesis; "If an adversary passes an
encoded command, the script block log will show the encoded-command option rather than a
readable script path" is.

**The negative cases.** Each must break exactly one requirement, and the manifest's
`rationale` must say which. Negatives that are unrelated noise pass trivially and catch no
regression. Walk the condition and disable one clause at a time.

## Contributing a correlation rule

Additionally:

- [ ] Base rules and the correlation document in one multi-document file
- [ ] Exactly one correlation document
- [ ] Base rules named, scored `informational`, and stated never to be alerted on directly
- [ ] Correlation type within `event_count`, `value_count`, `temporal`,
      `temporal_ordered`
- [ ] ≥ 2 positive and ≥ 2 negative sequences
- [ ] Negatives cover **ordering, grouping, threshold, and timespan** — one property each

See [`docs/correlation-subset.md`](docs/correlation-subset.md).

## Contributing code

- Match the existing style: frozen dataclasses, explicit configuration passing, no global
  mutable state.
- Respect the layer model in [`docs/architecture.md`](docs/architecture.md). Imports point
  downward only.
- Analysers return findings; they do not raise. Exceptions are reserved for conditions
  that make the run meaningless, and those map to exit code 3.
- Full type annotations; mypy runs strict.
- Docstrings explain *why*, not *what*. The existing modules are the reference.
- Add tests. See [`docs/testing.md`](docs/testing.md) for what needs covering.

### Changes needing extra care

| Change | Also required |
|---|---|
| New modifier or condition operator | Update `config/evaluator-profile.json`, document the semantics, test the boundaries |
| New quality gate | Define pass, fail, **and unproven**; changelog note, because it can turn a green build red |
| New report format | Determinism and injection-safety tests |
| New conversion backend | Must run offline; record which rules it declines and why |
| ATT&CK dataset update | Follow the process in `config/upstream-versions.json`; expect existing mappings to need decisions |
| Relaxing a safety limit | Will be rejected unless the threat it mitigates is re-analysed in `docs/threat-model.md` |

## Commit and pull-request conventions

Conventional Commits:

```
feat(rules): add SDEL-WIN-017 for signed binary proxy execution
fix(matcher): correct cidr handling for IPv6 fixtures
docs(coverage): clarify that technique counts are not coverage
test(correlation): add timespan boundary cases for SDEL-COR-003
chore(deps): pin pysigma to 1.5.0
```

Scopes: `rules`, `fixtures`, `metadata`, `matcher`, `correlation`, `gates`, `attack`,
`conversion`, `reports`, `cli`, `config`, `docs`, `ci`, `deps`.

A pull request should state what changed, why, which rules or modules it affects, and the
output of `sigma-detection-lab validate --strict`. If it changes matcher semantics or adds
a gate, say so prominently — those change what past results meant.

## Review criteria

| Area | Question |
|---|---|
| Originality | Is this the contributor's own work? |
| Synthetic data | Is every value from the permitted vocabulary? |
| Hypothesis | Is it falsifiable and stated in one sentence? |
| Telemetry | Are prerequisites and gaps stated honestly? |
| False positives | Three specific scenarios with actors and reasons? |
| Tuning | Does the guidance preserve detection value? |
| Negatives | Does each break exactly one requirement? |
| ATT&CK | Verified against the vendored catalog? |
| Claims | Any overstatement of what the evidence supports? |
| Gates | Does `--strict` pass? |

## What will not be accepted

- Copied rules from any source.
- Real data of any kind.
- Invented ATT&CK identifiers.
- `status: stable`, or maturity above `tested-synthetic`.
- Efficacy metrics computed from synthetic fixtures.
- Relaxed safety limits without a re-analysed threat model.
- Network access at runtime, in any form, for any reason.
- Deployment automation or SIEM integration — explicitly out of scope.
- Gate changes made to turn a red build green rather than to fix content.

## Reporting problems

**Security issues:** report privately per [`SECURITY.md`](SECURITY.md). Never include real
logs, credentials, or exploit payloads in a public issue.

**Bugs:** include the command, the full output, the exit code,
`sigma-detection-lab version --format json`, and your OS and Python version.

**Documentation:** claims that overstate what this project proves are treated as security
issues, not editorial ones, because false confidence in detection coverage has operational
consequences. Report them accordingly.

## License

Contributions are licensed under the MIT License. By contributing you confirm you have the
right to license the content that way, and that it is your own original work.

## Related documents

[rule-authoring-guide](docs/rule-authoring-guide.md) ·
[detection-philosophy](docs/detection-philosophy.md) ·
[rule-quality-gates](docs/rule-quality-gates.md) ·
[testing](docs/testing.md) ·
[architecture](docs/architecture.md)
