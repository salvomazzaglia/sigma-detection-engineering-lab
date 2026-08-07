# Development Plan — sigma-detection-engineering-lab 1.0.0

## Objective

Build an offline detection-as-code laboratory for authoring, validating, testing,
documenting, mapping, comparing, and converting original Sigma detection rules.

## Scope (v1.0)

- Original Sigma rules (minimum 56) with sidecars, fixtures, and quality gates
- Deterministic synthetic telemetry and behavioral tests
- Documented Sigma matcher and correlation subsets
- MITRE ATT&CK technique and verified defensive-object mappings
- Offline Splunk / Elasticsearch Lucene conversions via official pySigma backends
- JSON, HTML, SARIF, JUnit, CSV, and ATT&CK Navigator outputs
- Cross-platform GitHub-hosted CI

## Out of scope (roadmap only)

Live SIEM integration, deployment, production log replay, EVTX/PCAP, malware,
adversary emulation, cloud APIs, ML/UBA, YARA/Suricata, automatic SARIF upload,
and SigmaHQ publication.

## Phases

1. Inspect directory and record this plan
2. Repository structure and metadata
3. Upstream version verification and pinning
4. Models, paths, safe YAML
5. pySigma validation
6. Project conventions
7. Sidecar metadata and schemas
8. Event and fixture models
9. Matcher subset
10. Correlation subset
11. ATT&CK catalogs
12. Telemetry catalog
13–17. Original rule families
18. Synthetic fixtures
19. Behavioral test runner
20. Quality gates
21. Coverage
22. Conversions
23. Comparison
24. Reports
25. CLI
26. Deterministic examples
27. Screenshot
28. pytest suite (≥280)
29. Ruff / mypy
30. CI with SHA-pinned Actions
31. Documentation
32–35. Validation, demos, security audit, fixes
36. Local Git initialization with noreply identity

## Safety constraints

- No SIEM connections
- No host log inspection
- No executable fixture payloads
- No copied SigmaHQ rules
- No invented ATT&CK IDs
- Offline runtime after dependency installation

## Author

Salvatore Mazzaglia (`salvomazzaglia`)
