"""Redaction of credentials and enforcement of synthetic-only fixture content."""

from __future__ import annotations

import pytest
from tests.conftest import make_case, make_event, make_finding, make_rule, make_sequence

from sigma_detection_engineering_lab.config import LabConfig
from sigma_detection_engineering_lab.fixture_loader import FixtureSet
from sigma_detection_engineering_lab.redaction import (
    EXAMPLE_EMAIL_DOMAINS,
    MAX_SCAN_LENGTH,
    REDACTED,
    SECRET_PATTERNS,
    SUSPICIOUS_COMMAND_PATTERNS,
    redact_finding,
    redact_findings,
    redact_text,
    redact_value,
    scan_fixtures_for_real_data,
    scan_fixtures_for_secrets,
    scan_rules_for_secrets,
    scan_text,
)
from sigma_detection_engineering_lab.rule_catalog import RuleCatalog
from sigma_detection_engineering_lab.severities import Severity

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + "a" * 36
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpM"
SLACK_TOKEN = "xoxb-1234567890-abcdefghij"


class TestSecretDetection:
    @pytest.mark.parametrize(
        ("text", "name"),
        [
            ("-----BEGIN RSA PRIVATE KEY-----", "private_key_block"),
            (f"key={AWS_KEY}", "aws_access_key_id"),
            (f"token: {GITHUB_TOKEN}", "github_token"),
            (f"slack {SLACK_TOKEN}", "slack_token"),
            (f"auth {JWT}", "jwt"),
            ("Authorization: Bearer abcdefghijklmnopqrst", "bearer_token"),
            ("https://user:hunter22@example.com/x", "basic_auth_url"),
            ("password=hunter22", "password_assignment"),
            ("net use /pass:hunter22", "command_line_password_flag"),
            ("Server=x;Pwd=hunter22;", "connection_string_password"),
        ],
    )
    def test_each_credential_shape_is_detected(self, text: str, name: str) -> None:
        assert name in {match.name for match in scan_text(text)}

    def test_clean_text_produces_no_matches(self) -> None:
        assert scan_text("C:\\Windows\\System32\\cmd.exe /c whoami") == ()

    def test_empty_text_produces_no_matches(self) -> None:
        assert scan_text("") == ()

    def test_a_match_carries_a_masked_preview(self) -> None:
        match = scan_text(f"key={AWS_KEY}")[0]
        assert "***" in match.preview

    def test_the_preview_does_not_reveal_the_secret(self) -> None:
        match = scan_text(f"key={AWS_KEY}")[0]
        assert AWS_KEY not in match.preview

    def test_a_short_value_is_previewed_briefly(self) -> None:
        match = scan_text("password=abcd")[0]
        assert match.preview.endswith("***")

    def test_credentials_are_critical_by_default(self) -> None:
        assert scan_text(f"key={AWS_KEY}")[0].severity is Severity.CRITICAL

    def test_suspicious_commands_can_be_included(self) -> None:
        text = "powershell -enc " + "A" * 40
        assert scan_text(text, include_suspicious_commands=True)

    def test_suspicious_commands_can_be_excluded(self) -> None:
        text = "powershell -enc " + "A" * 40
        assert scan_text(text, include_suspicious_commands=False) == ()

    def test_encoded_powershell_is_high_not_critical(self) -> None:
        text = "powershell -enc " + "A" * 40
        matches = [m for m in scan_text(text) if m.name == "encoded_powershell"]
        assert matches[0].severity is Severity.HIGH

    def test_a_long_base64_blob_is_flagged(self) -> None:
        assert "long_base64_blob" in {match.name for match in scan_text("A" * 130)}

    def test_scanning_is_length_bounded(self) -> None:
        padding = "x" * (MAX_SCAN_LENGTH + 100)
        beyond = scan_text(padding + f" key={AWS_KEY}", include_suspicious_commands=False)
        assert beyond == ()

    def test_a_match_serialises(self) -> None:
        payload = scan_text(f"key={AWS_KEY}")[0].to_dict()
        assert set(payload) == {"name", "description", "severity", "preview"}

    def test_every_pattern_has_a_description(self) -> None:
        assert all(entry.description for entry in SECRET_PATTERNS)

    def test_every_suspicious_pattern_has_a_description(self) -> None:
        assert all(entry.description for entry in SUSPICIOUS_COMMAND_PATTERNS)

    def test_pattern_names_are_unique(self) -> None:
        names = [entry.name for entry in (*SECRET_PATTERNS, *SUSPICIOUS_COMMAND_PATTERNS)]
        assert len(set(names)) == len(names)


class TestRedactText:
    def test_a_whole_match_is_replaced(self) -> None:
        assert redact_text(f"key={AWS_KEY}") == f"key={REDACTED}"

    def test_the_secret_never_survives(self) -> None:
        assert AWS_KEY not in redact_text(f"aws {AWS_KEY} end")

    def test_only_the_captured_group_is_replaced(self) -> None:
        redacted = redact_text("password=hunter22")
        assert redacted.startswith("password=")
        assert "hunter22" not in redacted

    def test_surrounding_context_survives(self) -> None:
        redacted = redact_text("cmd.exe /c net use /pass:hunter22 && echo done")
        assert "cmd.exe" in redacted and "echo done" in redacted

    def test_clean_text_is_unchanged(self) -> None:
        text = "C:\\Windows\\System32\\cmd.exe"
        assert redact_text(text) == text

    def test_empty_text_is_unchanged(self) -> None:
        assert redact_text("") == ""

    def test_multiple_secrets_are_all_replaced(self) -> None:
        redacted = redact_text(f"{AWS_KEY} and {GITHUB_TOKEN}")
        assert AWS_KEY not in redacted and GITHUB_TOKEN not in redacted

    def test_redaction_is_idempotent(self) -> None:
        once = redact_text(f"key={AWS_KEY}")
        assert redact_text(once) == once

    def test_suspicious_commands_can_be_left_alone(self) -> None:
        text = "powershell -enc " + "A" * 40
        assert redact_text(text, include_suspicious_commands=False) == text

    def test_the_original_value_is_unrecoverable(self) -> None:
        redacted = redact_text("api_key=s3cr3tvalue123")
        assert "s3cr3tvalue123" not in redacted


class TestRedactValue:
    def test_a_string_is_redacted(self) -> None:
        assert redact_value(f"key={AWS_KEY}") == f"key={REDACTED}"

    def test_a_mapping_is_walked(self) -> None:
        assert redact_value({"a": f"key={AWS_KEY}"})["a"] == f"key={REDACTED}"

    def test_nested_mappings_are_walked(self) -> None:
        result = redact_value({"a": {"b": f"key={AWS_KEY}"}})
        assert AWS_KEY not in result["a"]["b"]

    def test_a_list_is_walked(self) -> None:
        assert AWS_KEY not in redact_value([f"key={AWS_KEY}"])[0]

    def test_a_tuple_becomes_a_list(self) -> None:
        assert isinstance(redact_value(("a",)), list)

    def test_integers_pass_through(self) -> None:
        assert redact_value(7) == 7

    def test_none_passes_through(self) -> None:
        assert redact_value(None) is None

    def test_booleans_pass_through(self) -> None:
        assert redact_value(True) is True

    def test_keys_are_preserved(self) -> None:
        assert set(redact_value({"alpha": "x", "beta": "y"})) == {"alpha", "beta"}


class TestFindingRedaction:
    def test_the_message_is_redacted(self) -> None:
        finding = make_finding(message=f"saw key={AWS_KEY}")
        assert AWS_KEY not in redact_finding(finding).message

    def test_the_remediation_is_redacted(self) -> None:
        finding = make_finding(remediation=f"remove key={AWS_KEY}")
        assert AWS_KEY not in redact_finding(finding).remediation

    def test_an_absent_remediation_stays_absent(self) -> None:
        assert redact_finding(make_finding(remediation=None)).remediation is None

    def test_other_fields_are_untouched(self) -> None:
        finding = make_finding(code="SDEL-X-001", subject="SUBJ")
        redacted = redact_finding(finding)
        assert redacted.code == "SDEL-X-001"
        assert redacted.subject == "SUBJ"

    def test_a_sequence_is_redacted(self) -> None:
        findings = redact_findings([make_finding(message=f"key={AWS_KEY}")])
        assert AWS_KEY not in findings[0].message

    def test_an_empty_sequence_is_handled(self) -> None:
        assert redact_findings([]) == ()

    def test_suspicious_commands_survive_finding_redaction(self) -> None:
        blob = "A" * 130
        assert blob in redact_finding(make_finding(message=blob)).message


class TestRuleSecretScanning:
    def test_a_clean_rule_produces_no_findings(self, simple_catalog: RuleCatalog) -> None:
        assert scan_rules_for_secrets(simple_catalog) == []

    def test_a_credential_in_a_detection_is_reported(self) -> None:
        rule = make_rule(
            detection={
                "selection": {"CommandLine": "login secret=hunter22"},
                "condition": "selection",
            }
        )
        findings = scan_rules_for_secrets(RuleCatalog([rule]))
        assert [finding.code for finding in findings] == ["SDEL-SEC-001"]

    def test_the_finding_names_the_rule(self) -> None:
        rule = make_rule(
            "SDEL-WIN-007",
            detection={"selection": {"CommandLine": "password=hunter22"}, "condition": "selection"},
        )
        assert scan_rules_for_secrets(RuleCatalog([rule]))[0].subject == "SDEL-WIN-007"

    def test_the_finding_names_the_gate(self) -> None:
        rule = make_rule(
            detection={"selection": {"CommandLine": "password=hunter22"}, "condition": "selection"}
        )
        assert scan_rules_for_secrets(RuleCatalog([rule]))[0].gate == "no_secrets"

    def test_encoded_powershell_detection_logic_is_allowed(self) -> None:
        rule = make_rule(
            detection={
                "selection": {"CommandLine|contains": "-enc " + "A" * 40},
                "condition": "selection",
            }
        )
        assert scan_rules_for_secrets(RuleCatalog([rule])) == []

    def test_field_names_are_scanned_too(self) -> None:
        rule = make_rule(
            detection={"selection": {"aws_secret_access_key": "x"}, "condition": "selection"}
        )
        assert isinstance(scan_rules_for_secrets(RuleCatalog([rule])), list)

    def test_an_empty_catalog_produces_no_findings(self) -> None:
        assert scan_rules_for_secrets(RuleCatalog([])) == []


class TestFixtureSecretScanning:
    def test_a_clean_fixture_produces_no_findings(self) -> None:
        assert scan_fixtures_for_secrets(FixtureSet(cases=(make_case(),))) == []

    def test_a_credential_in_a_fixture_is_reported(self) -> None:
        event = make_event(fields={"CommandLine": "login password=hunter22"})
        findings = scan_fixtures_for_secrets(FixtureSet(cases=(make_case(event=event),)))
        assert [finding.code for finding in findings] == ["SDEL-SEC-002"]

    def test_sequences_are_scanned(self) -> None:
        event = make_event(fields={"CommandLine": "password=hunter22"})
        fixtures = FixtureSet(sequences=(make_sequence(events=(event,)),))
        assert len(scan_fixtures_for_secrets(fixtures)) == 1

    def test_repeats_in_one_file_are_reported_once(self) -> None:
        event = make_event(fields={"a": "password=hunter22", "b": "password=other123"})
        fixtures = FixtureSet(cases=(make_case(event=event),))
        assert len(scan_fixtures_for_secrets(fixtures)) == 1

    def test_an_empty_fixture_set_produces_no_findings(self, empty_fixture_set: FixtureSet) -> None:
        assert scan_fixtures_for_secrets(empty_fixture_set) == []


class TestSyntheticDataEnforcement:
    def test_a_declared_synthetic_host_passes(self, tiny_config: LabConfig) -> None:
        fixtures = FixtureSet(cases=(make_case(event=make_event(host="SYNTHETIC-HOST-01")),))
        assert scan_fixtures_for_real_data(fixtures, tiny_config) == []

    def test_a_prefixed_host_passes(self, tiny_config: LabConfig) -> None:
        fixtures = FixtureSet(cases=(make_case(event=make_event(host="synthetic-web-99")),))
        assert scan_fixtures_for_real_data(fixtures, tiny_config) == []

    def test_a_real_looking_host_is_reported(self, tiny_config: LabConfig) -> None:
        fixtures = FixtureSet(cases=(make_case(event=make_event(host="prod-dc-01")),))
        codes = {f.code for f in scan_fixtures_for_real_data(fixtures, tiny_config)}
        assert codes == {"SDEL-SEC-010"}

    def test_a_declared_synthetic_user_passes(self, tiny_config: LabConfig) -> None:
        event = make_event(user="synthetic-admin")
        assert (
            scan_fixtures_for_real_data(FixtureSet(cases=(make_case(event=event),)), tiny_config)
            == []
        )

    def test_a_qualified_windows_account_passes(self, tiny_config: LabConfig) -> None:
        event = make_event(user="SYNTHETIC\\synthetic-admin")
        assert (
            scan_fixtures_for_real_data(FixtureSet(cases=(make_case(event=event),)), tiny_config)
            == []
        )

    def test_a_real_looking_user_is_reported(self, tiny_config: LabConfig) -> None:
        event = make_event(user="CORP\\jsmith")
        codes = {
            f.code
            for f in scan_fixtures_for_real_data(
                FixtureSet(cases=(make_case(event=event),)), tiny_config
            )
        }
        assert "SDEL-SEC-011" in codes

    def test_an_absent_user_is_not_reported(self, tiny_config: LabConfig) -> None:
        event = make_event(user=None)
        assert (
            scan_fixtures_for_real_data(FixtureSet(cases=(make_case(event=event),)), tiny_config)
            == []
        )

    @pytest.mark.parametrize(
        "address",
        ["10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "192.0.2.5", "203.0.113.9"],
    )
    def test_non_routable_addresses_pass(self, tiny_config: LabConfig, address: str) -> None:
        event = make_event(fields={"DestinationIp": address})
        assert (
            scan_fixtures_for_real_data(FixtureSet(cases=(make_case(event=event),)), tiny_config)
            == []
        )

    @pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1"])
    def test_routable_addresses_are_reported(self, tiny_config: LabConfig, address: str) -> None:
        event = make_event(fields={"DestinationIp": address})
        codes = {
            f.code
            for f in scan_fixtures_for_real_data(
                FixtureSet(cases=(make_case(event=event),)), tiny_config
            )
        }
        assert codes == {"SDEL-SEC-012"}

    @pytest.mark.parametrize(
        "domain", sorted(EXAMPLE_EMAIL_DOMAINS - {"invalid", "localhost", "test"})
    )
    def test_reserved_email_domains_pass(self, tiny_config: LabConfig, domain: str) -> None:
        event = make_event(fields={"Recipient": f"user@{domain}"})
        assert (
            scan_fixtures_for_real_data(FixtureSet(cases=(make_case(event=event),)), tiny_config)
            == []
        )

    def test_a_real_email_domain_is_reported(self, tiny_config: LabConfig) -> None:
        event = make_event(fields={"Recipient": "user@acme-corp.co.uk"})
        codes = {
            f.code
            for f in scan_fixtures_for_real_data(
                FixtureSet(cases=(make_case(event=event),)), tiny_config
            )
        }
        assert codes == {"SDEL-SEC-013"}

    def test_duplicate_reports_are_collapsed(self, tiny_config: LabConfig) -> None:
        event = make_event(fields={"a": "8.8.8.8", "b": "8.8.8.8"})
        fixtures = FixtureSet(cases=(make_case(event=event),))
        assert len(scan_fixtures_for_real_data(fixtures, tiny_config)) == 1

    def test_sequence_events_are_examined(self, tiny_config: LabConfig) -> None:
        event = make_event(host="prod-dc-01")
        fixtures = FixtureSet(sequences=(make_sequence(events=(event,)),))
        assert len(scan_fixtures_for_real_data(fixtures, tiny_config)) == 1

    def test_the_gate_is_named(self, tiny_config: LabConfig) -> None:
        fixtures = FixtureSet(cases=(make_case(event=make_event(host="prod-dc-01")),))
        finding = scan_fixtures_for_real_data(fixtures, tiny_config)[0]
        assert finding.gate == "no_real_data_patterns"

    def test_the_remediation_is_actionable(self, tiny_config: LabConfig) -> None:
        fixtures = FixtureSet(cases=(make_case(event=make_event(host="prod-dc-01")),))
        assert "SYNTHETIC-" in scan_fixtures_for_real_data(fixtures, tiny_config)[0].remediation

    def test_an_empty_fixture_set_produces_no_findings(
        self, tiny_config: LabConfig, empty_fixture_set: FixtureSet
    ) -> None:
        assert scan_fixtures_for_real_data(empty_fixture_set, tiny_config) == []


class TestRealContent:
    def test_no_real_rule_embeds_a_credential(self, real_catalog: RuleCatalog) -> None:
        assert [f.subject for f in scan_rules_for_secrets(real_catalog)] == []

    def test_no_real_fixture_embeds_a_credential(self, real_fixtures: FixtureSet) -> None:
        assert [f.subject for f in scan_fixtures_for_secrets(real_fixtures)] == []

    def test_every_real_fixture_looks_synthetic(
        self, real_fixtures: FixtureSet, real_config: LabConfig
    ) -> None:
        findings = scan_fixtures_for_real_data(real_fixtures, real_config)
        assert [f"{f.code}:{f.message}" for f in findings] == []
