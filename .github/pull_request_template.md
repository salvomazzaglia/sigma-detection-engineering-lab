## Summary

<!-- What does this PR change and why? -->

## Detection engineering checklist

- [ ] Rules are original to this project (no SigmaHQ copies)
- [ ] Sidecar metadata exists and matches Sigma UUID / catalog ID
- [ ] Positive and negative synthetic fixtures included
- [ ] False-positive considerations are specific
- [ ] ATT&CK IDs verified against the pinned catalog (or explicit unmapped reason)
- [ ] No real logs, secrets, domains, or personal paths
- [ ] No live SIEM integration or network runtime calls
- [ ] Status is experimental or test (not stable)
- [ ] Maturity is experimental or tested-synthetic
- [ ] Tests and quality gates pass locally

## Validation performed

```text
python -m sigma_detection_engineering_lab validate --rules rules --metadata metadata/rules --strict
python -m pytest -q
```

## Risk notes

<!-- Tuning risk, unsupported constructs, conversion limitations -->
