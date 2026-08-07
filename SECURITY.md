# Security Policy — sigma-detection-engineering-lab

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Reporting a vulnerability

Please report security issues privately to the repository owner via GitHub Security Advisories when available, or via a private contact channel associated with the `salvomazzaglia` GitHub account.

Do not open public issues that include:

- Real logs, alerts, or credentials
- Exploit payloads
- Production detection bypass details that enable harm

## In-scope concerns

- Unsafe YAML parsing or resource exhaustion via crafted rule/fixture files
- Regex denial of service in the lab matcher
- Secret or real-log exposure in repository content or reports
- Rule-evaluator bypass that causes unsupported constructs to be reported as passing
- Conversion output injection into reports
- Path traversal or symlink escape outside the project root
- HTML/CSV injection in generated reports
- Supply-chain compromise of dependencies or GitHub Actions
- Misleading coverage or false confidence claims in documentation

## Out of scope

- SIEM product vulnerabilities
- Production detection efficacy against real adversaries
- Issues that require live SIEM connectivity (this project does not connect)

## Response expectations

Reports will be acknowledged when practical. Fixes for confirmed issues will be documented in `CHANGELOG.md` and, for the 1.0.0 baseline, in `docs/security-audit-v1.0.0.md` updates as appropriate.

Never include secret values in public discussions.
