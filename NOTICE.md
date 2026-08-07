# NOTICE

This project is independent of SigmaHQ and MITRE.

## Sigma

The Sigma detection rule format and specification are maintained by the SigmaHQ
community. This repository uses the official Sigma specification (pinned in
`config/upstream-versions.json`) and the pySigma ecosystem for parsing and
offline query conversion demonstrations.

Sigma and SigmaHQ names and logos are trademarks or property of their respective
owners. This project does not claim official SigmaHQ certification, endorsement,
or community-rule status.

Original detection rules in this repository are authored specifically for this
project and are not copies of SigmaHQ community rules.

## pySigma and backends

Runtime conversion demonstrations use official SigmaHQ packages:

- pySigma (`LGPL-2.1-only` per PyPI / upstream LICENSE)
- pysigma-backend-splunk (`LGPL-2.1-only` per PyPI / upstream LICENSE)
- pysigma-backend-elasticsearch (LGPL family per upstream package metadata)

Those packages retain their upstream licenses. The MIT license of this
repository applies to original project content only and does not replace
upstream license terms for third-party dependencies.

## MITRE ATT&CK®

MITRE ATT&CK® is a registered trademark of The MITRE Corporation.

This project vendors a minimal subset of ATT&CK Enterprise identifiers and names
for offline validation of analytical metadata. Inclusion of ATT&CK identifiers
does not imply MITRE certification, endorsement, or complete coverage.

Any redistributed ATT&CK content in `data/attack/` is reproduced under the
MITRE ATT&CK Terms of Use. Required attribution:

© 2026 The MITRE Corporation. This work is reproduced and distributed with the
permission of The MITRE Corporation.

Legacy ATT&CK Data Sources are deprecated in the current defensive model.
This project prefers Detection Strategies, Analytics, and Data Components where
verified against the pinned ATT&CK dataset.

## Navigator

ATT&CK Navigator layer files follow the published layer format specification.
This project does not claim official Navigator endorsement.

## Project license

Original project code, original Sigma rules authored for this repository,
synthetic fixtures, and project documentation are licensed under the MIT License
(see `LICENSE`), except where upstream package licenses apply to third-party
dependencies and where ATT&CK redistributed content remains under the MITRE
Terms of Use reproduced above.
