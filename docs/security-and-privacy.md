# Security and privacy

This document describes the security properties of the laboratory itself: what it will and
will not do to the machine it runs on, and what data it can and cannot expose.

## Structural guarantees

These are properties of the design, not configuration options.

| Guarantee | How it is achieved |
|---|---|
| **No network access at runtime** | No module imports a network client. There is no SIEM connection, no ATT&CK download, no telemetry, no update check. |
| **No host log access** | The laboratory reads only files inside its own project root. It never opens an event log, `/var/log`, or a journal. |
| **No code execution** | Fixtures are data. Nothing is `eval`ed, imported, or executed. There is no plugin loader. |
| **No privilege requirement** | Runs as an unprivileged user. Nothing requires administrator or root. |
| **No writable state outside the project** | Writes go to `temp/` or to explicitly requested output paths, all inside the root. |

Removing network capability from the design removes a whole class of accidental
exfiltration. It is a structural property, not a default.

## Path safety

`paths.py` applies these checks to every filesystem operation:

| Control | Behaviour |
|---|---|
| Root containment | Every resolved path must be inside the project root; escapes raise `PathSafetyError` |
| Symlink refusal | `allow_symlinks: false` — symlinks are not followed |
| Path length | Capped at `max_path_length` (4096) |
| File size | Capped at `max_file_bytes` (1 048 576) before reading |
| Traversal | Paths are resolved and re-checked after resolution, so `../` cannot escape |

`generate-demo` applies the same rule to its output and refuses to write outside the root,
with an explicit message. That is not paranoia about the user; the example has to live
inside the project to be validatable against its configuration.

## Hardened YAML

Rule files are the primary untrusted input. `yaml_loader.py` wraps PyYAML's safe loader
with limits enforced **during** construction rather than after:

| Limit | Value | Attack prevented |
|---|---|---|
| `max_yaml_depth` | 32 | Stack exhaustion through deep nesting |
| `max_yaml_nodes` | 5000 | Memory exhaustion through node count |
| `max_yaml_aliases` | **0** | Billion-laughs alias expansion |
| `max_scalar_length` | 8192 | Memory exhaustion through a single scalar |
| `max_mapping_size` | 512 | Oversized mappings |
| `max_sequence_length` | 512 | Oversized sequences |

Two additional refusals matter as much as the limits:

**Duplicate keys are rejected.** PyYAML silently keeps the last value. A rule could
therefore present one `condition` to a human reviewer and a different one to the parser.
That is a review-bypass primitive, and it is refused.

**Custom tags are rejected.** No `!!python/object`, no unknown tags. Only plain YAML data.

Enforcing during construction rather than after parsing matters: a post-hoc check on a
parsed document has already paid the memory cost of parsing it.

## Regex safety

Regular expressions in rules are attacker-influenced input that CI executes:

- **Maximum length 256** (`max_regex_length`).
- **Catastrophic-backtracking rejection.** Nested unbounded quantifiers — the `(a+)+`
  shape — are refused before compilation.
- Compilation failure is a finding, not a crash.
- A rejected pattern yields `UNSUPPORTED`, so the rule cannot pass by being unevaluatable.

## Secret detection and redaction

`redaction.py` does two distinct jobs.

**Redaction** strips credential-shaped strings from report content before it is written. A
finding message quoting rule text cannot leak a secret into a published report or a SARIF
file uploaded to a code-scanning service.

**Detection** scans rules and fixtures for content that should not exist:

| Pattern family | Examples |
|---|---|
| API keys and tokens | Provider-prefixed keys, long high-entropy strings |
| Bearer tokens | `Authorization: Bearer ...` |
| Private keys | `-----BEGIN ... PRIVATE KEY-----` |
| Connection strings | URIs with embedded credentials |
| Password assignments | `password=`, `pwd=`, `secret=` with a value |

Detections feed the `no_secrets` gate, which blocks.

## Real-data detection

A separate scan looks for content that is not synthetic:

| Check | Rejects |
|---|---|
| IP addresses | Anything routable; only `192.0.2.0/24` is permitted |
| Email domains | Anything outside `example.invalid` and `synthetic.invalid` |
| Hostnames | Anything outside the approved synthetic vocabulary |
| Paths | Windows paths outside `C:\Synthetic\`, Linux paths outside the synthetic tree |

Feeds the `no_real_data_patterns` gate, which blocks. This is the guard rail that matters
most if you fork the laboratory and point it at your own content.

## Report injection safety

Rule text reaches reports, and rule text is untrusted:

| Format | Control |
|---|---|
| HTML | All interpolated values are escaped. The report is **standalone and offline**: no CDN, no external font, no script tag. |
| CSV | Leading `=`, `+`, `-`, and `@` are neutralised so a spreadsheet cannot execute a formula. |
| SARIF | JSON-encoded; no `security-severity`, so quality findings cannot masquerade as vulnerabilities. |
| JUnit | Attributes quoted and text escaped via `xml.sax.saxutils`. |
| JSON | Standard encoding with `ensure_ascii=False` and sorted keys. |

The HTML report being fully self-contained is a security property as well as a convenience
one: opening it cannot cause a network request.

## SARIF and misclassification

Every finding this project emits describes the quality of *detection content* — a missing
sidecar, an unverifiable ATT&CK identifier, a placeholder false positive. None describes
an exploitable weakness in software. Presenting them as vulnerabilities would inflate a
code-scanning dashboard with non-issues.

So the SARIF writer asserts the distinction explicitly:

- No rule carries `security-severity`, so findings do not contribute to a security score.
- Every rule is tagged `detection-engineering` and `quality`.
- The run and every rule descriptor carry `isVulnerabilityFinding: false` and a note
  stating these are quality findings.

## Privacy

**No personal data exists in this repository.** No real account names, hostnames, IP
addresses, email addresses, or organizational identifiers.

Placeholder identities use reserved namespaces that cannot resolve or route:

| Namespace | Reservation |
|---|---|
| `example.invalid`, `synthetic.invalid` | RFC 2606 — `.invalid` never resolves |
| `192.0.2.0/24` | RFC 5737 — documentation range, not routable |

A copy-paste accident therefore cannot produce a request to a real host.

## Dependency and supply chain

- Runtime dependencies pinned exactly: `pysigma==1.5.0`,
  `pysigma-backend-splunk==2.1.0`, `pysigma-backend-elasticsearch==2.1.0`.
- GitHub Actions pinned to full commit SHAs, not tags:
  `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`,
  `actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97`.
- Workflow permissions restricted to `contents: read`.
- `config/upstream-versions.json` records the verification date and a documented update
  process.
- Ruff's `S` (bandit) rules run in CI; mypy runs in strict mode.

Pinning to SHAs rather than tags matters because a tag can be moved. A SHA cannot.

## Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md). Report privately via GitHub Security Advisories.
Never include real logs, credentials, or exploit payloads in a public issue.

In scope: unsafe YAML parsing, regex denial of service, secret or real-log exposure,
evaluator bypass that lets unsupported constructs report as passing, conversion output
injection, path traversal or symlink escape, HTML/CSV injection, supply-chain compromise,
and misleading coverage or false-confidence claims in documentation.

Out of scope: SIEM product vulnerabilities, production detection efficacy, and anything
requiring live SIEM connectivity.

That last in-scope item is unusual and deliberate. A documentation claim that overstates
what this project proves is treated as a security issue, because false confidence in
detection coverage has operational consequences.

## Related documents

[threat-model](threat-model.md) ·
[security-audit-v1.0.0](security-audit-v1.0.0.md) ·
[synthetic-event-model](synthetic-event-model.md) ·
[reports](reports.md)
