# Fine-Tuning Plan: english-slm-110m for Compliance

**Model:** english-slm-110m (109.5M params, LLaMA-style, 2048 context, 32K vocab)  
**Hardware:** Single H200 SXM, BF16, Flash Attention 2  
**Date:** 2026-03-16

---

## Stage 1: Domain-Adaptive Pretraining (DAPT)

**Goal:** Teach the model compliance vocabulary, clause structure, and framework patterns before any task-specific training.

### Data Source

`data/raw/full/` — ~16.5M tokens across 12 frameworks:

| Source | Format | Size |
|---|---|---|
| NIST 800-53 Rev 5 | JSON | ~10.4M chars |
| MITRE ATT&CK Enterprise | JSON | ~45.1M chars |
| FedRAMP (Low/Mod/High) | JSON | ~3.4M chars |
| CIS Benchmarks | HTML | ~1.7M chars |
| HIPAA (Parts 160/162/164) | HTML | ~1.3M chars |
| GDPR | HTML | ~1.1M chars |
| CMMC (32 CFR Part 170) | HTML | ~384K chars |
| CCPA (§1798.100–199) | TXT | ~366K chars |
| PCI DSS v4.0.1 | PDF text | ~395K chars |
| SOC2 TSC Overview | HTML | ~358K chars |
| ISO 27001 Overview | HTML | ~123K chars |
| NIST CSF v2.0 | PDF text | ~1.5M chars |

### Data Preparation

1. **Extract plain text** from each source:
   - JSON files (NIST, FedRAMP, MITRE): extract human-readable fields (control description, supplemental guidance, technique description)
   - HTML files (HIPAA, GDPR, CIS, CMMC, SOC2, ISO): extract body text, strip tags
   - PDF text / TXT files: use as-is with light cleanup
2. **Chunk into 2048-token documents** with ~128-token overlap at boundaries
3. **Hold out 5%** of chunks for validation

### Training Configuration

| Setting | Value |
|---|---|
| Objective | Causal LM (next-token prediction) |
| Learning rate | 2e-5 |
| Warmup | 5% of total steps |
| Epochs | 2–3 |
| Batch size | 32–64 (fill H200 memory) |
| Weight decay | 0.01 |
| Precision | BF16 + Flash Attention 2 |

### Validation

- Track perplexity on held-out compliance chunks
- Compare against base model perplexity — expect significant drop
- Estimated training time: < 1 hour on H200

---

## Stage 2: Supervised Fine-Tuning (SFT)

**Goal:** Train the DAPT checkpoint on specific compliance tasks using labeled data.

### General SFT Settings

| Setting | Value |
|---|---|
| Learning rate | 5e-5 to 1e-4 |
| Epochs | 3–5 |
| Batch size | 16–32 |
| Max sequence length | 2048 tokens (input + target) |
| Prompt format | `<s>[INST] {input} [/INST] {target}</s>` |
| Fine-tuning mode | Full (not LoRA — 110M fits easily in memory) |
| Eval split | 10% held-out |

Train tasks in order below. Validate each before proceeding to the next.

---

### Task 2.1: Framework Tagging / Routing

**Objective:** Given a compliance control or requirement description (with framework tag removed), predict which framework it belongs to.

**Labels:** 12 classes — `NIST_800_53`, `MITRE_ATTACK`, `FEDRAMP`, `CIS_BENCHMARKS`, `HIPAA`, `GDPR`, `ISO_27001`, `NIST_CSF`, `PCI_DSS`, `CCPA`, `CMMC`, `SOC2`

**Input/Target Format:**
```json
{
  "input": "Classify framework: Ensure that backup information is tested to verify media reliability and information integrity.",
  "target": "NIST_800_53"
}
```

**Data Construction:**
- Extract control/requirement descriptions from raw source files
- Strip framework identifiers from the text
- Label = source framework

**Volume:** ~500 per framework → ~6,000 total

**Metric:** Top-1 accuracy (target: ≥ 90%)

---

### Task 2.2: Control Family Mapping

**Objective:** Given a compliance control description, predict its control family.

**Labels:**
- NIST 800-53: AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PM, PS, PT, RA, SA, SC, SI, SR (20 families)
- MITRE ATT&CK: Tactic abbreviations (TA00xx) or technique prefixes (T1xxx top-level)
- CIS: Section numbers (1.x, 2.x, etc.)

**Input/Target Format:**
```json
{
  "input": "Map to control family: Log the execution of privileged functions to detect misuse.",
  "target": "AU"
}
```

**Data Construction:**
- Parse NIST JSON catalog — strip control ID from description, use family prefix as label
- Parse MITRE JSON — use tactic as label
- Parse CIS HTML — use section number as label

**Volume:** ~5,000 total

**Metric:** Top-1 accuracy (target: ≥ 85%)

---

### Task 2.3: Compliance Classification

**Objective:** Given a compliance control and an event/evidence description, classify the compliance status.

**Labels:** `COMPLIANT`, `NON_COMPLIANT`, `INSUFFICIENT_EVIDENCE`

**Input/Target Format:**
```json
{
  "input": "Control: SC-8 Transmission Confidentiality. Event: Firewall logs confirm TLS 1.2 on all port 443 traffic.",
  "target": "COMPLIANT"
}
```

**Data Construction:**
- Pair real control descriptions (from raw sources) with synthetic event descriptions
- Use GPT-4 / Claude to generate candidate event+control pairs with labels
- Manually review ≥ 10% sample for quality
- Ensure roughly balanced label distribution (aim for 30/40/30 split)

**Volume:** 3,000–5,000 examples

**Metric:** Macro-F1 across 3 classes (target: ≥ 80%)

---

### Task 2.4: Structured Field Extraction

**Objective:** Given a raw compliance control text, extract structured JSON fields.

**Output Fields:** `framework`, `control_id`, `control_name`, `category`

**Input/Target Format:**
```json
{
  "input": "Extract fields: [nist_800_53] sc-7.12 Host-based Protection. Implement host-based firewalls at servers and workstations.",
  "target": "{\"framework\": \"NIST_800_53\", \"control_id\": \"SC-7.12\", \"control_name\": \"Host-based Protection\", \"category\": \"System and Communications Protection\"}"
}
```

**Data Construction:**
- Parse NIST JSON catalog — structured fields already exist in source
- Parse MITRE JSON — technique ID, name, tactic already structured
- Parse FedRAMP JSON — control ID, baseline level already structured
- Combine text description with structured label as target

**Volume:** 3,000–5,000 examples

**Metric:** Per-field exact match accuracy (target: ≥ 85% per field)

---

### Task 2.5: Grounded Rationale Generation

**Objective:** Given a control + event pair, produce a short compliance assessment with status, reasoning, and remediation recommendation.

**Input/Target Format:**
```json
{
  "input": "Control: SC-8. Event: HTTP traffic on port 80 with no encryption. Assess and explain.",
  "target": "NON_COMPLIANT. SC-8 requires transmission confidentiality. Unencrypted HTTP on port 80 violates this requirement. Remediation: enforce TLS on all external connections."
}
```

**Data Construction:**
- Generate using GPT-4 / Claude with carefully designed prompts
- Mandate 3-part structure: status → reasoning → remediation
- Cap target length at ~100 tokens (fits 110M model capacity)
- Manually review ≥ 10% for factual accuracy against source controls

**Volume:** ~2,000 examples

**Metric:** Human evaluation on coherence + factual grounding; automated ROUGE-L against reference (target: ≥ 0.6)

---

## Optional: Multi-Task Fine-Tuning Pass

After all 5 tasks are individually trained and validated, optionally combine all datasets with task-specific prefixes and run a final unified SFT pass:

```
Task: classify_framework Text: ...
Task: map_control_family Text: ...
Task: classify_compliance Control: ... Event: ...
Task: extract_fields Text: ...
Task: assess_compliance Control: ... Event: ...
```

This teaches the model to dispatch based on the task token, producing a single checkpoint that handles all 5 tasks.

---

## Summary

| Step | Action | Data Source | Volume | Estimated Time |
|---|---|---|---|---|
| Stage 1 | DAPT — causal LM on compliance text | `data/raw/full/` | ~16.5M tokens | < 1 hr (H200) |
| Task 2.1 | Framework tagging | Raw source extraction | ~6,000 | ~30 min (H200) |
| Task 2.2 | Control family mapping | Raw source extraction | ~5,000 | ~30 min (H200) |
| Task 2.3 | Compliance classification | Synthetic generation + review | 3,000–5,000 | ~30 min (H200) |
| Task 2.4 | Structured extraction | Raw source parsing | 3,000–5,000 | ~30 min (H200) |
| Task 2.5 | Grounded rationales | Synthetic generation + review | ~2,000 | ~30 min (H200) |

**Bottleneck:** Labeled dataset construction (Stage 2), not training compute.
