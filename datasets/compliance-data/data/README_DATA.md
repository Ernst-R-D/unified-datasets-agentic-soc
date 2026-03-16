# Compliance Training Data Prep

This folder holds raw/manual/processed compliance training data for:

- ComplianceSLM multi-task format
- FLAN-T5 text-to-text format

## 1) Run data prep

From project root:

```bash
python scripts/prepare_compliance_packs.py
```

## 2) What is downloaded automatically

- NIST SP 800-53 Rev 5 OSCAL JSON (public machine-readable catalog)

## 3) What you should add manually

Place plain-text packs in `data/manual/`:

- `hipaa.txt`
- `pci_dss.txt`
- `iso_27001.txt`
- `soc2.txt`
- `gdpr.txt`
- `ccpa.txt`
- `cis_benchmarks.txt`
- `mitre_attack.txt`
- `fedramp.txt`
- `cmmc.txt`
- `nist_csf.txt`

The parser expects one control chunk per paragraph (blank-line separated).

## 4) Output files

Generated in `data/processed/`:

- `compliance_multitask.jsonl`
- `compliance_multitask_train.jsonl`
- `compliance_multitask_val.jsonl`
- `compliance_multitask_test.jsonl`
- `compliance_t5.jsonl`
- `compliance_t5_train.jsonl`
- `compliance_t5_val.jsonl`
- `compliance_t5_test.jsonl`
- `dataset_manifest.json`
- `dataset_summary.json`

## 5) Record formats

### Multi-task (ComplianceSLM-compatible)

```json
{
  "text": "[CONTROL] HIPAA §164.308 ...",
  "framework_label": 4,
  "status_label": 3,
  "risk_label": 4,
  "control_label": 2,
  "remediation_label": 0,
  "sensitivity_labels": [0,1,0,0,0,0,0,1],
  "category": "compliance_pack",
  "meta": {"framework": "hipaa", "control_id": "§164.308", "title": "...", "source": "..."}
}
```

### T5 (FLAN-T5/LongT5)

```json
{
  "input": "Task: compliance_control_parse\\nText: [hipaa] §164.308 ...",
  "target": "{\"framework\":\"hipaa\",\"status\":\"not_applicable\",...}"
}
```

## Notes

- Some standards (for example PCI DSS commercial materials) may be license-restricted; place text you are authorized to use in `data/manual/`.
- Review and enrich labels (`status_label`, `risk_label`, `remediation_label`) before final supervised training if you need high-fidelity operational outputs.
