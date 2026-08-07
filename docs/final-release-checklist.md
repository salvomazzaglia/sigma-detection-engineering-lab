# Final release checklist — 1.0.0

Run top to bottom. Every box must be ticked or explicitly waived with a recorded reason.

## 1. Version consistency

- [x] `VERSION` contains `1.0.0`
- [x] `pyproject.toml` `version = "1.0.0"`
- [x] `src/sigma_detection_engineering_lab/__init__.py` `__version__ = "1.0.0"`
- [x] `CHANGELOG.md` has a `1.0.0` entry with a date
- [x] `docs/release-notes-v1.0.0.md` exists
- [x] README version badge reads `1.0.0`

```bash
sigma-detection-lab version --format json
```

## 2. Upstream pins

- [x] Sigma specification 2.1.0, commit `0c857d07da0e71eaaab2d667b3cce6f2c8469578`
- [x] pySigma 1.5.0
- [x] `pysigma-backend-splunk` 2.1.0
- [x] `pysigma-backend-elasticsearch` 2.1.0
- [x] ATT&CK Enterprise 19.1, STIX `ATT&CK-v19.1`
- [x] Navigator layer format 4.5
- [x] `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` # v7.0.1
- [x] `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065` # v5.6.0
- [x] `verification_date` current in `config/upstream-versions.json`
- [x] Pins in `pyproject.toml` match `config/upstream-versions.json`

```bash
python scripts/validate-upstream-catalog.py
```

## 3. Catalog

- [x] 56 rules — 50 standard, 6 correlation
- [x] 56 sidecars, one per rule, bound by UUID
- [x] 12 distinct logsources
- [x] 36 techniques, 6 tactics, all verified against the vendored subset
- [x] No duplicate UUIDs
- [x] No duplicate catalog identifiers
- [x] Every filename matches the convention
- [x] Every UUID re-derivable from its catalog identifier

```bash
sigma-detection-lab list-rules
sigma-detection-lab coverage
```

## 4. Fixtures

- [x] 253 cases and 30 correlation sequences — 283 results
- [x] Every standard rule ≥ 2 positive and ≥ 3 negative
- [x] Every correlation rule ≥ 2 positive and ≥ 2 negative sequences
- [x] Every negative breaks exactly one requirement
- [x] Correlation negatives cover ordering, grouping, threshold, and timespan
- [x] Every event carries `synthetic: true`
- [x] Only the permitted synthetic vocabulary appears
- [x] No decodable encoded content

## 5. Quality gates

- [x] All 31 gates pass
- [x] No gate disabled without a recorded reason
- [x] `--strict` produces exit 0

```bash
sigma-detection-lab validate --strict --json-out temp/release.json
```

## 6. Behavioral tests

- [x] 283 results, all passing
- [x] 0 failed, 0 errored, 0 **unsupported**, 0 skipped
- [x] Evaluator recorded as `sdel-lab-matcher-v1`

```bash
sigma-detection-lab test --junit-out temp/tests.xml
```

## 7. Conversion

- [x] Splunk: 53 converted, 3 unsupported, 0 errors
- [x] Elasticsearch Lucene: 50 converted, 6 unsupported, 0 errors
- [x] Every unsupported result records the backend's reason
- [x] Every emitted query carries the demonstration banner
- [x] Correlation limitation documented
- [x] No SIEM connection attempted

```bash
sigma-detection-lab convert --backend splunk --output temp/splunk.json
sigma-detection-lab convert --backend elasticsearch-lucene --output temp/es.json
```

## 8. Reports

- [x] JSON validates against `schemas/quality-report.schema.json`
- [x] HTML is standalone — no CDN, no script, no external font
- [x] SARIF carries no `security-severity` and sets `isVulnerabilityFinding: false`
- [x] JUnit renders `UNSUPPORTED` as a failure, not a skip
- [x] CSV neutralises formula-injection prefixes
- [x] Navigator layer is format 4.5 with verified techniques only
- [x] All four banners appear verbatim
- [x] `production_ready: false` in every machine-readable report
- [x] Two runs differ only in `generated_at`

## 9. Security

- [x] `no_secrets` passes
- [x] `no_real_data_patterns` passes
- [x] `safe_yaml_load` passes for all 56 files
- [x] Path containment and symlink refusal verified
- [x] Regex limits enforced
- [x] Report injection controls verified
- [x] No network client in the package
- [x] `docs/security-audit-v1.0.0.md` complete

## 10. Documentation

- [x] README covers all 40 sections, with badges, Mermaid diagram, and screenshot
- [x] All 30 `docs/*.md` present
- [x] `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `NOTICE.md`, `LICENSE`
- [x] `examples/README.md` and `examples/sample-conversions/README.md`
- [x] `fixtures/README.md` and `metadata/README.md`
- [x] Screenshot present at `docs/images/sample-detection-engineering-report.png`
- [x] Internal links resolve
- [x] No production-readiness, coverage, or certification claims
- [x] Independence from SigmaHQ and MITRE stated in README and NOTICE
- [x] Author and repository URL correct throughout

## 11. Examples

- [x] `examples/rules/`, `examples/metadata/`, `examples/fixtures/` complete
- [x] Sample reports in JSON, HTML, SARIF, JUnit, CSV
- [x] Navigator layer sample
- [x] Sample conversions for both backends, all 56 rules
- [x] `generate-demo` reproduces a valid example

```bash
sigma-detection-lab generate-demo --output examples/demo --force
sigma-detection-lab validate --rules examples/demo/rules \
  --metadata examples/demo/metadata/rules --fixtures examples/demo/fixtures
```

## 12. Static analysis and build

- [x] `ruff check src tests scripts` clean
- [x] `ruff format --check src tests scripts` clean
- [x] `mypy src` clean in strict mode
- [x] `python -m build` produces a wheel and an sdist
- [x] `py.typed` included in the wheel

## 13. Cross-platform

- [x] Ubuntu, Python 3.11 and 3.12
- [x] Windows, Python 3.11 and 3.12
- [x] Console encoding handled on legacy Windows code pages
- [x] LF line endings in all generated output on both platforms

## 14. Repository hygiene

- [x] No `temp/` artefacts committed
- [x] No `.mypy_cache/`, `.ruff_cache/`, or `__pycache__/` committed
- [x] No scratch files committed
- [x] `.gitignore`, `.gitattributes`, `.editorconfig` present

## Outstanding items

None blocking local packaging. Previously noted gaps were closed before the
1.0.0 local commit:

- pytest suite present (2782 passed, 6 skipped)
- CI workflow aligned to the documented CLI surface

## Release commands

```bash
python scripts/clean-generated-files.py
python -m pip install -e ".[dev]"
python scripts/run-ci.py

sigma-detection-lab validate --strict --json-out temp/release-1.0.0.json
sigma-detection-lab compare temp/previous.json temp/release-1.0.0.json

python -m build
git tag -a v1.0.0 -m "sigma-detection-engineering-lab 1.0.0"
```

## Post-release

- [ ] Tag pushed
- [ ] Release notes published from `docs/release-notes-v1.0.0.md`
- [ ] `temp/release-1.0.0.json` retained as the comparison baseline
- [ ] Remote topics and GitHub release created only after explicit publication approval

## Related documents

[release-notes-v1.0.0](release-notes-v1.0.0.md) ·
[security-audit-v1.0.0](security-audit-v1.0.0.md) ·
[rule-lifecycle](rule-lifecycle.md) ·
[testing](testing.md)
