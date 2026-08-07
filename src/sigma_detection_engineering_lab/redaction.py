"""Redaction of secrets and detection of non-synthetic data in reports.

Two related jobs live here.

**Redaction** rewrites credential-shaped strings before they reach a report.
Detection content quotes command lines by nature, and a fixture author can paste
a real token into one without noticing. Reports are committed and published, so
redaction happens on the way out, every time.

**Synthetic-data enforcement** is the inverse check. This project promises that
every fixture is generated, so anything resembling real infrastructure — a
hostname outside the declared synthetic set, a routable public address, a
non-example email domain — is reported as a possible leak of real data.

Redaction is intentionally lossy. A redacted value cannot be recovered from the
report, which is the point.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.fixture_loader import FixtureSet
from sigma_detection_engineering_lab.models import (
    FindingCategory,
    ValidationFinding,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.severities import Severity

REDACTED: Final[str] = "[REDACTED]"

MAX_SCAN_LENGTH: Final[int] = 65_536
"""Values longer than this are truncated before scanning, bounding regex work."""


@dataclass(frozen=True)
class RedactionPattern:
    """One named credential shape."""

    name: str
    pattern: re.Pattern[str]
    description: str
    severity: Severity = Severity.CRITICAL
    group: int = 0
    """Which capture group to replace. 0 replaces the whole match."""


SECRET_PATTERNS: Final[tuple[RedactionPattern, ...]] = (
    RedactionPattern(
        name="private_key_block",
        pattern=re.compile(r"-----BEGIN [A-Z ]{0,32}PRIVATE KEY-----"),
        description="PEM private key header",
    ),
    RedactionPattern(
        name="aws_access_key_id",
        pattern=re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        description="AWS access key identifier",
    ),
    RedactionPattern(
        name="aws_secret_access_key",
        pattern=re.compile(
            r"(?i)\baws_?secret_?access_?key\b\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})",
        ),
        description="AWS secret access key",
        group=1,
    ),
    RedactionPattern(
        name="github_token",
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,255}\b"),
        description="GitHub personal access or app token",
    ),
    RedactionPattern(
        name="slack_token",
        pattern=re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        description="Slack API token",
    ),
    RedactionPattern(
        name="jwt",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        description="JSON Web Token",
    ),
    RedactionPattern(
        name="bearer_token",
        pattern=re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})"),
        description="HTTP bearer credential",
        group=1,
    ),
    RedactionPattern(
        name="basic_auth_url",
        pattern=re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]{3,})@"),
        description="credential embedded in a URL",
        group=1,
    ),
    RedactionPattern(
        name="password_assignment",
        pattern=re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)"
            r"\b\s*[=:]\s*['\"]?([^\s'\";,&]{4,})"
        ),
        description="password or key assignment",
        group=1,
    ),
    RedactionPattern(
        name="command_line_password_flag",
        pattern=re.compile(
            r"(?i)(?:^|\s)(?:-p|--password|/pass(?:word)?:|-Password)\s*[= ]?\s*"
            r"(?!\s)([^\s'\"]{4,})"
        ),
        description="password supplied on a command line",
        group=1,
    ),
    RedactionPattern(
        name="connection_string_password",
        pattern=re.compile(r"(?i)\b(?:pwd|password)\s*=\s*([^;\s]{4,});"),
        description="database connection string password",
        group=1,
    ),
)

SUSPICIOUS_COMMAND_PATTERNS: Final[tuple[RedactionPattern, ...]] = (
    RedactionPattern(
        name="encoded_powershell",
        pattern=re.compile(r"(?i)-(?:e|ec|enc|encoded|encodedcommand)\s+([A-Za-z0-9+/=]{24,})"),
        description="base64-encoded PowerShell payload",
        severity=Severity.HIGH,
        group=1,
    ),
    RedactionPattern(
        name="long_base64_blob",
        pattern=re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b"),
        description="long base64 blob",
        severity=Severity.MEDIUM,
    ),
)

EXAMPLE_EMAIL_DOMAINS: Final[frozenset[str]] = frozenset(
    {"example.com", "example.org", "example.net", "invalid", "localhost", "test"}
)

EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24})\b"
)

IPV4_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SYNTHETIC_PREFIXES: Final[tuple[str, ...]] = ("synthetic-", "synthetic_", "lab-", "test-")

SYNTHETIC_QUALIFIERS: Final[frozenset[str]] = frozenset({"synthetic", "lab", "test", "local"})
"""Bare domain or workgroup names accepted as the qualifier in ``DOMAIN\\user``.

``SYNTHETIC\\synthetic-admin`` is the realistic shape of a Windows account name,
and its domain part carries no prefix to check.
"""


@dataclass(frozen=True)
class SecretMatch:
    """One credential-shaped substring found during a scan."""

    name: str
    description: str
    severity: Severity
    preview: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "severity": str(self.severity),
            "preview": self.preview,
        }


def _preview(value: str) -> str:
    """Render a short, already-masked hint so a reviewer can locate the match."""
    collapsed = " ".join(value.split())
    if len(collapsed) <= 12:
        return f"{collapsed[:2]}***"
    return f"{collapsed[:6]}***{collapsed[-2:]}"


def scan_text(
    text: str,
    *,
    include_suspicious_commands: bool = True,
) -> tuple[SecretMatch, ...]:
    """Return every credential-shaped match in ``text`` without altering it."""
    if not text:
        return ()
    subject = text[:MAX_SCAN_LENGTH]
    patterns = (
        (*SECRET_PATTERNS, *SUSPICIOUS_COMMAND_PATTERNS)
        if include_suspicious_commands
        else SECRET_PATTERNS
    )
    matches: list[SecretMatch] = []
    for entry in patterns:
        for found in entry.pattern.finditer(subject):
            captured = found.group(entry.group) if entry.group else found.group(0)
            if not captured:
                continue
            matches.append(
                SecretMatch(
                    name=entry.name,
                    description=entry.description,
                    severity=entry.severity,
                    preview=_preview(captured),
                )
            )
    return tuple(matches)


def redact_text(text: str, *, include_suspicious_commands: bool = True) -> str:
    """Return ``text`` with every credential-shaped substring replaced.

    Only the captured credential is replaced, not the surrounding context, so a
    redacted command line remains readable as a detection artefact.
    """
    if not text:
        return text

    patterns = (
        (*SECRET_PATTERNS, *SUSPICIOUS_COMMAND_PATTERNS)
        if include_suspicious_commands
        else SECRET_PATTERNS
    )
    result = text
    for entry in patterns:
        if entry.group == 0:
            result = entry.pattern.sub(REDACTED, result)
            continue

        def replace(match: re.Match[str], group: int = entry.group) -> str:
            whole = match.group(0)
            captured = match.group(group)
            if not captured:
                return whole
            start = match.start(group) - match.start(0)
            end = match.end(group) - match.start(0)
            return whole[:start] + REDACTED + whole[end:]

        result = entry.pattern.sub(replace, result)
    return result


def redact_value(value: Any, *, include_suspicious_commands: bool = True) -> Any:
    """Recursively redact strings inside mappings, sequences, and scalars."""
    if isinstance(value, str):
        return redact_text(value, include_suspicious_commands=include_suspicious_commands)
    if isinstance(value, Mapping):
        return {
            key: redact_value(item, include_suspicious_commands=include_suspicious_commands)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [
            redact_value(item, include_suspicious_commands=include_suspicious_commands)
            for item in value
        ]
    return value


def _finding(
    code: str,
    severity: Severity,
    subject: str,
    message: str,
    *,
    path: str | None = None,
    gate: str | None = None,
    remediation: str | None = None,
) -> ValidationFinding:
    return ValidationFinding(
        code=code,
        category=FindingCategory.SAFETY,
        severity=severity,
        subject=subject,
        message=message,
        path=path,
        gate=gate,
        remediation=remediation,
    )


def _iter_strings(value: Any, depth: int = 0) -> list[str]:
    if depth > 8:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        collected: list[str] = []
        for key, item in value.items():
            if isinstance(key, str):
                collected.append(key)
            collected.extend(_iter_strings(item, depth + 1))
        return collected
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        collected = []
        for item in value:
            collected.extend(_iter_strings(item, depth + 1))
        return collected
    return []


def scan_rules_for_secrets(catalog: RuleCatalog) -> list[ValidationFinding]:
    """Scan rule detection content for credential-shaped values.

    Suspicious command patterns are excluded here: detection rules legitimately
    match on encoded PowerShell, and flagging that would make the gate useless.
    """
    findings: list[ValidationFinding] = []
    for rule in catalog:
        for text in _iter_strings(rule.detection):
            for match in scan_text(text, include_suspicious_commands=False):
                findings.append(
                    _finding(
                        "SDEL-SEC-001",
                        match.severity,
                        rule.catalog_id,
                        f"rule detection contains a possible {match.description} ({match.preview})",
                        path=rule.relative_path,
                        gate="no_secrets",
                        remediation=(
                            "Replace the literal with a synthetic placeholder; detection "
                            "logic should never embed a real credential."
                        ),
                    )
                )
    return findings


def scan_fixtures_for_secrets(fixtures: FixtureSet) -> list[ValidationFinding]:
    """Scan fixture events for credential-shaped values."""
    findings: list[ValidationFinding] = []
    seen: set[tuple[str, str]] = set()

    def examine(catalog_id: str, source: str, payload: Mapping[str, Any]) -> None:
        for text in _iter_strings(payload):
            for match in scan_text(text, include_suspicious_commands=False):
                key = (source, match.name)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    _finding(
                        "SDEL-SEC-002",
                        match.severity,
                        catalog_id,
                        f"fixture contains a possible {match.description} ({match.preview})",
                        path=source,
                        gate="no_secrets",
                        remediation="Replace the value with an obviously synthetic placeholder.",
                    )
                )

    for case in fixtures.cases:
        examine(case.catalog_id, case.source_path, dict(case.event.fields))
    for sequence in fixtures.sequences:
        for event in sequence.events:
            examine(sequence.catalog_id, sequence.source_path, dict(event.fields))
    return findings


def _is_synthetic_name(value: str, allowed: Sequence[str]) -> bool:
    """Return whether a host or account name is recognisably synthetic.

    Account names arrive qualified in several conventions -- ``DOMAIN\\user``,
    ``HOST\\user``, ``user@domain`` -- and each part must be synthetic on its own.
    Checking the whole string would reject ``SYNTHETIC\\synthetic-admin``, which
    is exactly the form a realistic Windows fixture uses.
    """
    text = value.strip()
    if not text:
        return True

    lowered_allowed = {item.strip().lower() for item in allowed}

    def is_synthetic(part: str) -> bool:
        lowered = part.strip().lower()
        return lowered in lowered_allowed or lowered.startswith(SYNTHETIC_PREFIXES)

    if is_synthetic(text):
        return True
    parts = [part for part in re.split(r"[\\/@]", text) if part.strip()]
    return len(parts) > 1 and all(
        is_synthetic(part) or part.strip().lower() in SYNTHETIC_QUALIFIERS for part in parts
    )


def _is_non_routable(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return True
    return bool(
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
        or parsed in ipaddress.ip_network("192.0.2.0/24")
        or parsed in ipaddress.ip_network("198.51.100.0/24")
        or parsed in ipaddress.ip_network("203.0.113.0/24")
    )


def scan_fixtures_for_real_data(
    fixtures: FixtureSet,
    config: LabConfig,
) -> list[ValidationFinding]:
    """Report fixture content that does not look synthetic.

    Checks hostnames and usernames against the configured synthetic sets, flags
    publicly routable IP addresses, and flags email domains outside the reserved
    example ranges.
    """
    findings: list[ValidationFinding] = []
    reported: set[tuple[str, str]] = set()

    def report(
        code: str,
        severity: Severity,
        catalog_id: str,
        source: str,
        message: str,
        remediation: str,
    ) -> None:
        key = (source, message)
        if key in reported:
            return
        reported.add(key)
        findings.append(
            _finding(
                code,
                severity,
                catalog_id,
                message,
                path=source,
                gate="no_real_data_patterns",
                remediation=remediation,
            )
        )

    def examine_event(catalog_id: str, source: str, event: Any) -> None:
        if not _is_synthetic_name(event.host, config.synthetic_hosts):
            report(
                "SDEL-SEC-010",
                Severity.HIGH,
                catalog_id,
                source,
                f"fixture host {event.host!r} is not one of the declared synthetic hosts",
                "Use a host from config synthetic_hosts, or prefix it with 'SYNTHETIC-'.",
            )
        if event.user and not _is_synthetic_name(event.user, config.synthetic_users):
            report(
                "SDEL-SEC-011",
                Severity.HIGH,
                catalog_id,
                source,
                f"fixture user {event.user!r} is not one of the declared synthetic users",
                "Use an account from config synthetic_users, or prefix it with 'synthetic-'.",
            )

        for text in _iter_strings(dict(event.fields)):
            for address in IPV4_PATTERN.findall(text):
                if not _is_non_routable(address):
                    report(
                        "SDEL-SEC-012",
                        Severity.MEDIUM,
                        catalog_id,
                        source,
                        f"fixture contains publicly routable address {address}",
                        "Use RFC 1918 space or the RFC 5737 documentation ranges.",
                    )
            for domain in EMAIL_PATTERN.findall(text):
                if domain.strip().lower() not in EXAMPLE_EMAIL_DOMAINS:
                    report(
                        "SDEL-SEC-013",
                        Severity.MEDIUM,
                        catalog_id,
                        source,
                        f"fixture contains an email address at non-example domain {domain!r}",
                        "Use an address at example.com or another reserved domain.",
                    )

    for case in fixtures.cases:
        examine_event(case.catalog_id, case.source_path, case.event)
    for sequence in fixtures.sequences:
        for event in sequence.events:
            examine_event(sequence.catalog_id, sequence.source_path, event)
    return findings


def redact_finding(finding: ValidationFinding) -> ValidationFinding:
    """Return a copy of a finding with its free-text fields redacted."""
    from dataclasses import replace

    return replace(
        finding,
        message=redact_text(finding.message, include_suspicious_commands=False),
        remediation=(
            redact_text(finding.remediation, include_suspicious_commands=False)
            if finding.remediation
            else finding.remediation
        ),
    )


def redact_findings(
    findings: Sequence[ValidationFinding],
) -> tuple[ValidationFinding, ...]:
    """Redact a whole sequence of findings before they enter a report."""
    return tuple(redact_finding(finding) for finding in findings)


__all__ = [
    "EMAIL_PATTERN",
    "EXAMPLE_EMAIL_DOMAINS",
    "REDACTED",
    "SECRET_PATTERNS",
    "SUSPICIOUS_COMMAND_PATTERNS",
    "SYNTHETIC_QUALIFIERS",
    "RedactionPattern",
    "SecretMatch",
    "redact_finding",
    "redact_findings",
    "redact_text",
    "redact_value",
    "scan_fixtures_for_real_data",
    "scan_fixtures_for_secrets",
    "scan_rules_for_secrets",
    "scan_text",
]
