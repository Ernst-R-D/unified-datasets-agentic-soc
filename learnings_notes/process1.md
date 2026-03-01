# Process 1 -- SecurityBERT from Scratch: Summary and Gap Analysis

## What Was Built

A BERT-based model (called SecurityBERT) trained from scratch for security log anomaly detection and threat classification. The pipeline has two phases:

- Phase 1: Masked Language Model (MLM) pretraining on 900k synthetic normal log sessions. The model learns what normal log sequences look like. After this phase, anomaly detection works by measuring how surprised the model is when it tries to reconstruct masked tokens in a new session. High reconstruction loss = anomaly.

- Phase 2: Supervised fine-tuning on 100k labeled sessions (70% normal, 30% attacks across 14 categories). Five classification heads are attached to the [CLS] token: threat category (14 classes), severity (5 levels), confidence (4 levels), true positive (binary), and attack surface (8 multi-label).

The final inference function `detect()` runs both stages: first checks if a session is anomalous via MLM loss, then classifies anomalous sessions.

## Architecture Details

- 6 encoder layers, 8 attention heads, hidden dim 256, feedforward dim 1024
- Roughly 9-14M parameters (small enough for a Colab T4)
- Custom BPE tokenizer with 8192 vocab, security-aware canonical patterns (IP addresses, LOLBins, CVEs, MITRE TTP IDs, Windows paths, etc. are each mapped to a single token before BPE)
- Pre-norm encoder blocks (LayerNorm before attention/FFN, not after)
- Learned positional embeddings, segment embeddings (unused in practice since there is only one segment)

## What Works Well

1. The two-phase training strategy is sound. MLM pretraining to learn normal patterns, then fine-tuning for classification, is a proven approach (the original BERT paper established this).

2. The custom tokenizer with canonical patterns is a good idea. Collapsing IPs, paths, hashes, LOLBins into single tokens gives the model meaningful units instead of wasting capacity on subword fragments of hex strings.

3. Span masking instead of single-token masking is a meaningful improvement over vanilla BERT MLM. Forces the model to reconstruct longer phrases from context.

4. The LogFuzzer for entity variation and noise injection is a step in the right direction. Prevents the model from memorizing fixed usernames/hosts.

5. Differential learning rates in Phase 2 (lower for pretrained encoder, higher for new classification heads) is correct practice for fine-tuning.

6. Multi-pass anomaly scoring (averaging MLM loss over 5 random masking passes) reduces variance compared to a single masking.

---

## Errors and Bugs

### 1. Cell ordering problem
Cell 2 defines `LogFuzzer` and calls `office_session()` and `generate_robust_session()`, but `office_session` is not defined until Cell 10, and `re` is not imported until Cell 5. If you run cells top to bottom, Cell 2 will crash with a NameError. The fuzzer definition should come after the session generators and imports.

### 2. Deprecated GradScaler usage
```python
scaler = torch.cuda.amp.GradScaler(enabled=(dtype == 'float16'))
```
`torch.cuda.amp.GradScaler` is deprecated in newer PyTorch versions. Use `torch.amp.GradScaler('cuda', enabled=...)` instead. Also, since the notebook defaults to bfloat16 on supported hardware, GradScaler is created but effectively disabled (GradScaler does nothing for bfloat16). This is not a bug per se, but the code is misleading -- it looks like mixed precision scaling is active when it is not.

### 3. Normal sessions always get threat_label=12 (policy_violation)
In `generate_normal_labeled()`, every normal session is labeled as `threat_label: 12` (policy violation), `severity: 4` (info), `tp_label: 0`. This means the fine-tuning classifier never sees a proper "benign/no-threat" class. The model is trained to think every input belongs to one of 14 threat categories, and normal sessions are just "policy_violation with low confidence." There is no explicit "normal" class. This is a design flaw -- the model cannot cleanly say "this is not a threat at all."

### 4. MLM label bug in dummy test
```python
dummy_mlm = dummy_ids.clone()
dummy_mlm[:, ::7] = -100
```
This sets every 7th position to -100 as the label, but those positions still have real token IDs in `dummy_ids`. The actual MLM training uses -100 to mean "do not compute loss here." The test is backwards -- labels should contain real token IDs at masked positions and -100 everywhere else. This does not affect training (it is only a shape test), but it shows a misunderstanding in the verification code.

### 5. Segment embeddings are wasted
`num_segments=2` and a segment embedding layer exists, but `token_type_ids` is always zeros (single sequence, no NSP task). The segment embedding contributes nothing useful but adds parameters and could confuse the model slightly during training (the embedding for segment 1 is never trained).

---

## Gaps for Real-World SIEM Log Classification

These are the things that will actually matter when you try to stream real SIEM logs through this model.

### Gap 1: Synthetic data will not survive contact with real logs

This is the single biggest problem. Every session in this notebook is generated by Python template functions. Real SIEM logs look nothing like this. Real logs have:

- Vendor-specific formats (Splunk, QRadar, Sentinel, ELK all structure logs differently)
- Syslog headers with facility/severity codes, hostnames, timestamps in multiple formats
- Multiline events (stack traces, Windows Event XML, JSON payloads)
- Field names that vary by source (src_ip vs sourceAddress vs SrcAddr)
- Volume differences (a single session might be 3 events or 3000 events)
- Encoding artifacts, truncation, missing fields, duplicate events

The model trained on synthetic templates will have learned the template grammar, not actual security semantics. When it sees a real Sysmon EventID 1 log or a Palo Alto firewall deny, it will produce garbage embeddings because the token distribution is completely different from training.

What to do: You need to pretrain on real logs. The notebook mentions this in Cell 34 but it is the most critical step. Get a few million normal sessions exported from your SIEM (Splunk searches, Sentinel KQL queries, etc.), convert them to a consistent text format, and retrain from scratch. The synthetic data can be used for initial testing and architecture validation only.

### Gap 2: Session boundary definition is unclear

The notebook assumes a "session" is a neat sequence of events between SESSION_START and SESSION_END. Real SIEM data does not have sessions. You need to define how to window raw events into sessions before the model can process them. Options:

- Fixed time windows (all events from one host in a 5-minute window)
- User-based sessions (all events tied to one user login until logout or timeout)
- Entity-based grouping (all events sharing a process tree or connection)

This windowing logic is not in the notebook and is a significant engineering task. It directly affects model performance -- too wide a window dilutes signal, too narrow misses multi-step attacks.

### Gap 3: No streaming/online inference architecture

The notebook runs batch inference. For real SIEM streaming, you need:

- A message queue consumer (Kafka, Azure Event Hub, etc.) that reads events in real time
- Session assembly logic that groups events into windows as they arrive
- Batched inference (accumulate N sessions, run them through the model together)
- Latency targets (how fast must you classify? Sub-second? Minutes?)
- A way to handle the model being slower than the event rate

None of this is in the notebook, which is expected for a training notebook, but it means there is a large gap between "model works in Colab" and "model processes live SIEM data."

### Gap 4: The 128-token max sequence length is very short

Real security sessions can have hundreds or thousands of events. With max_seq_len=128 and [CLS]/[SEP] taking 2 positions, you have 126 usable tokens. After BPE, a realistic session might need 500-2000 tokens. The current model will truncate and throw away most of the session.

Options to address:
- Increase max_seq_len (512 or 1024), which increases memory quadratically with attention
- Use hierarchical approach: encode chunks of events separately, then aggregate
- Use a sliding window with aggregation over the session

### Gap 5: No handling of class imbalance in real data

Real SIEM data is extremely imbalanced. In production, 99.9% or more of logs are normal. The notebook uses 70% normal / 30% attacks for fine-tuning. When you switch to real data, you will have maybe 0.1% true attacks. The classification heads will need:

- Oversampling of attack classes or undersampling of normal
- Class-weighted loss functions (the code has label smoothing but not class weights)
- Focal loss instead of cross entropy for the rare classes
- Evaluation metrics that handle imbalance (precision-recall curves, F1 per class, not just accuracy)

### Gap 6: No evaluation beyond accuracy

The notebook tracks threat_acc and tp_acc during training. For a security model, you need:

- Per-class precision, recall, and F1 (some threat categories might have 95% accuracy but 0% recall)
- False positive rate at various thresholds (SOC analysts will reject a model that generates too many false alerts)
- Detection latency (how many events into an attack session before the model flags it)
- Confusion matrix between threat categories (is the model confusing lateral movement with exfiltration?)
- ROC/AUC curves for the anomaly scorer

### Gap 7: Anomaly threshold calibration is fragile

The threshold is set as mean + 2 sigma on 500 synthetic normal sessions. This calibration:

- Uses synthetic data (will not transfer to real logs)
- Uses only 500 samples (not statistically robust for production)
- Assumes normal MLM loss is roughly Gaussian (may not be true)
- Has no mechanism for drift (the threshold is static, but log patterns change over time as infrastructure changes, new apps are deployed, etc.)

In production, you need to recalibrate regularly and monitor for distribution shift.

### Gap 8: No concept of temporal patterns

The model treats a session as a bag of tokens with positional encoding. It does not explicitly model:

- Time gaps between events (a login followed by a file read 1 second later vs 3 hours later)
- Event frequency/rate (100 failed logins in 10 seconds vs 10 minutes)
- Periodicity (C2 beaconing often has regular intervals)

The positional embedding captures ordering but not timing. For real threat detection, time features matter a lot.

### Gap 9: The canonical pattern list is Windows-centric

The regex patterns cover Windows paths, registry paths, LOLBins, and Event IDs well. But real SIEM environments also have:

- Linux/Mac process events (no .exe extension, different path structures)
- Cloud provider logs (AWS CloudTrail, Azure Activity, GCP Audit)
- Network device logs (firewalls, proxies, load balancers)
- Email gateway logs
- Container/Kubernetes audit logs

The canonical patterns need to be expanded significantly, or you need a more flexible entity extraction approach.

### Gap 10: No model versioning or A/B testing framework

When you retrain on real data, you need to compare the new model against the old one. The notebook saves a single checkpoint. In production you need:

- Model registry with versioned artifacts
- Shadow mode (run new model alongside old one, compare outputs before switching)
- Rollback capability
- Performance tracking over time

---

## Where You Are vs Where You Need to Be

What you have built is a correct and reasonable proof of concept. The architecture (BERT encoder, two-phase training, custom tokenizer, dual anomaly+classification inference) is sound. The code runs and produces results on synthetic data.

The gap between this and a production SIEM classifier is primarily in the data. The model architecture will likely work fine with minor adjustments (longer sequence length, maybe more layers). But the model needs to be trained on real logs to be useful. Everything else -- streaming infrastructure, session windowing, threshold calibration, evaluation metrics -- follows from having real data to work with.

Immediate next steps in order of priority:

1. Get real SIEM logs (you mentioned you are downloading a dataset -- this is the right move)
2. Write a log parser/normalizer that converts your SIEM format into the session text format the model expects
3. Retrain the tokenizer on real logs (the BPE merges learned on synthetic data will not transfer)
4. Retrain Phase 1 on real normal sessions
5. Get labeled incidents from your SOC (closed tickets, known-good alerts) for Phase 2
6. Add proper evaluation metrics before retraining Phase 2
7. Increase max_seq_len to at least 256, ideally 512
8. Add a proper "normal/benign" class to the classification head instead of overloading policy_violation
