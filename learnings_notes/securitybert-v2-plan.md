# SecurityBERT v2 -- Build Plan

This is the step-by-step plan to build a production-grade SecurityBERT model that can classify real SIEM logs as normal or threat. Each step is a self-contained piece of work. Do them in order. Do not skip ahead.

---

## Step 0: Understand what we are building

A BERT encoder model that takes a stream of SIEM log events and answers two questions:
1. Is this session normal or anomalous? (anomaly detection via MLM loss)
2. If anomalous, what kind of threat is it? (classification via [CLS] head)

The model must be log-agnostic. It should work the same whether the input is a Windows Sysmon event, a Palo Alto firewall log, an AWS CloudTrail entry, or a CrowdStrike alert. The normalization layer handles vendor differences. The model only sees a clean, uniform text format.

What we keep from process1:
- The BERT architecture (encoder layers, attention, MLM head, classification heads)
- The two-phase training strategy (Phase 1 MLM pretrain, Phase 2 supervised fine-tune)
- The custom BPE tokenizer class
- The canonical pattern regexes (with expansions)
- The anomaly scoring function (MLM loss based)

What we rebuild:
- The entire data pipeline (parsers, normalizer, session windowing)
- The tokenizer training (on real data, not synthetic)
- The training data itself (real logs, not template-generated)
- The evaluation code (proper metrics, not just accuracy)
- The classification labels (add a "normal" class)

---

## Step 1: Build the Unified Event Schema

**What:** Define a single flat structure that every log event gets converted to, regardless of vendor.

**The schema:**

```
timestamp        -- when (ISO 8601 string)
event_type       -- what happened (one of a fixed set, see below)
log_source       -- which vendor/product produced this log
source_ip        -- who initiated
dest_ip          -- target IP
source_host      -- hostname of the machine that generated the event
dest_host        -- target hostname (if applicable)
user             -- user identity associated with this event
process_name     -- process involved
parent_process   -- parent process name
command_line     -- full command line (if applicable)
file_path        -- file or registry path involved
dest_port        -- destination port
protocol         -- network protocol (TCP, UDP, HTTP, DNS, etc.)
action           -- what the vendor says happened (allow, deny, block, execute, etc.)
severity         -- vendor-reported severity (if any)
event_id         -- vendor event ID (Windows EventID, etc.)
mitre_technique  -- MITRE ATT&CK technique ID if known
raw_extra        -- overflow field, anything important that does not fit above
```

**Fixed event_type values:**

```
process_create, process_terminate
file_read, file_write, file_delete, file_rename
net_connect, net_listen, net_deny
dns_query, dns_response
auth_success, auth_fail, auth_logout
registry_write, registry_read, registry_delete
service_create, service_modify
scheduled_task_create
user_create, user_modify, user_delete
group_modify
policy_change
alert
email_receive, email_send
cloud_api_call
system_boot, system_shutdown
other
```

This list covers the event types that matter for security. If a log does not map cleanly to any of these, use "other."

**Output of this step:** A Python dataclass or dict schema definition. A function `to_model_text(event_dict) -> str` that flattens the dict to a single text line. Only include fields that have values. Skip empty fields.

Example output:

```
[TIMESTAMP] event_type=process_create log_source=sysmon source_host=ws-042 user=admin process_name=ntdsutil.exe parent_process=cmd.exe command_line="ntdsutil ac i ntds ifm create full [WIN_PATH]" event_id=4688
```

---

## Step 2: Write log parsers

**What:** One parser function per log format. Each parser takes raw input and returns a list of unified event dicts.

**Parsers to write (in priority order):**

### Parser 1: Windows Event XML
- Covers: All 51 Splunk .log files (1.07M events). This is your biggest dataset.
- Input: XML string like `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>...</Event>`
- Extract: EventID, TimeCreated, Computer, SubjectUserName, NewProcessName, ParentProcessName, CommandLine, TargetIP, etc.
- Map EventID to event_type:
  - 4688 -> process_create
  - 4689 -> process_terminate
  - 4624 -> auth_success
  - 4625 -> auth_fail
  - 4634 -> auth_logout
  - 4663 -> file_read or file_write (check AccessMask)
  - 4657 -> registry_write
  - 1 (Sysmon) -> process_create
  - 3 (Sysmon) -> net_connect
  - 11 (Sysmon) -> file_write
  - 13 (Sysmon) -> registry_write
  - 22 (Sysmon) -> dns_query
  - etc.

### Parser 2: Elastic integration JSON
- Covers: All files under elastic/ directory (~5,600 events across 257 data streams)
- Input: JSON dict with nested vendor-specific structure
- Each package (crowdstrike, panw, aws, okta, etc.) has different nested field paths
- Strategy: Write a generic flattener that walks the JSON tree and maps known field names (regardless of nesting) to unified fields. For example, if the JSON has `destination.ip` anywhere in the tree, map it to `dest_ip`. If it has `process.name`, map to `process_name`.
- Common ECS (Elastic Common Schema) field mappings:
  - `source.ip` -> source_ip
  - `destination.ip` -> dest_ip
  - `destination.port` -> dest_port
  - `process.name` -> process_name
  - `process.parent.name` -> parent_process
  - `process.command_line` -> command_line
  - `user.name` -> user
  - `host.name` -> source_host
  - `event.action` -> action
  - `event.severity` -> severity

### Parser 3: Sentinel ASIM CSV
- Covers: 76 ingested log CSV files
- Input: CSV with columns like TenantId, TimeGenerated, Computer, RawData, Message
- The actual log content is usually in the RawData or Message column
- RawData often contains embedded syslog. Parse the syslog header, then parse the payload.

### Parser 4: EVTX binary
- Covers: 30 .evtx files
- Requires: python-evtx library
- Each EVTX record contains Windows Event XML. Parse it into XML, then reuse Parser 1.

**Output of this step:** A Python module with functions: `parse_windows_xml(text) -> list[dict]`, `parse_elastic_json(data) -> list[dict]`, `parse_sentinel_csv(filepath) -> list[dict]`, `parse_evtx(filepath) -> list[dict]`. All return lists of unified event dicts.

---

## Step 3: Run parsers on all raw data

**What:** Process every file in the raw_logs directory and produce a single pool of normalized events.

**How:**
1. Walk through every file in raw_logs/
2. Detect format (XML/JSON/CSV/EVTX) and call the right parser
3. Write all normalized events to a single JSONL file: `normalized_events.jsonl`
4. Each line: `{"timestamp": "...", "event_type": "...", "log_source": "...", ...}`
5. Also write a metadata sidecar: how many events per source, per event_type, per log_source

**Expected output:**
- Splunk XML: ~1.07M events (all attack data, labeled by MITRE technique from filename)
- Elastic JSON: ~5,600 events (mix of normal and alert)
- Sentinel CSV: variable (mix)
- EVTX: variable (all attack data, labeled by filename category)

**Tag each event:**
- `label`: "attack" or "normal" or "unknown"
- `mitre_technique`: extracted from filename (e.g., T1003) or from event content if available
- `attack_category`: mapped from MITRE technique to your threat categories (credential_theft, lateral_movement, etc.)

The MITRE technique to threat category mapping:
```
T1003, T1110, T1078, T1098         -> credential_theft
T1021, T1570                        -> lateral_movement
T1059, T1204, T1053, T1047         -> execution (malware)
T1071, T1572                        -> c2
T1486                               -> ransomware
T1566                               -> phishing
T1055, T1134, T1548                 -> priv_esc
T1041, T1567                        -> exfiltration
T1046, T1033, T1049, T1016, T1018  -> recon
T1190, T1133                        -> web_attack
T1499                               -> dos
T1014                               -> defense_evasion
```

You will not have perfect coverage. Some techniques map to multiple categories. Pick the primary one. The point is to get a usable labeled dataset, not a perfect taxonomy.

**Output of this step:** `normalized_events.jsonl` with all events, each tagged with source, label, and category where known.

---

## Step 4: Session windowing

**What:** Group individual events into sessions. The model processes sessions, not individual events.

**How:**

For attack data (Splunk/EVTX files):
- Events from the same file that share the same Computer (hostname) and SubjectUserName, ordered by timestamp, form a session.
- If there is a gap of more than 10 minutes between consecutive events, split into separate sessions.
- This gives you natural attack sessions: "what did this user do on this machine during this attack reproduction?"

For normal/mixed data (Elastic, Sentinel):
- Group by (source_host, user) within a 5-minute sliding window.
- If no user or host, group by log_source within a time window.

**Session format:**

Each session becomes a single text string. Concatenate the normalized text of each event in the session, separated by a delimiter:

```
[CLS] event_type=auth_success log_source=sysmon source_host=ws-042 user=admin event_id=4624 [EVT_SEP] event_type=process_create log_source=sysmon source_host=ws-042 user=admin process_name=ntdsutil.exe parent_process=cmd.exe command_line="ntdsutil ac i ntds ifm create full [WIN_PATH]" event_id=4688 [EVT_SEP] event_type=file_write log_source=sysmon source_host=ws-042 user=admin file_path=[WIN_PATH] event_id=11 [SEP]
```

`[EVT_SEP]` is a new special token that separates events within a session. Add it to the tokenizer special tokens list.

**Output of this step:**
- `pretrain_sessions.jsonl` -- sessions for Phase 1 (normal data only, no labels)
- `finetune_sessions.jsonl` -- sessions for Phase 2 (labeled, both normal and attack)

Each line: `{"text": "...", "label": "normal"|"attack", "threat_category": "...", "mitre": "T1003", "source_file": "..."}`

---

## Step 5: Get more normal data

**What:** Your dataset is heavily attack-biased. Phase 1 needs large volumes of normal logs. Phase 2 also needs a healthy proportion of normal sessions.

**Options (pick one or combine):**

Option A: Public datasets
- LANL Unified Host and Network Dataset (auth.txt.gz, proc.txt.gz, flows.txt.gz) -- millions of real enterprise events, mostly normal, with a small set of red team events labeled. This is the best public option for your use case.
- BETH dataset -- 8M events from a honeypot, with benign/malicious labels.
- CICIDS 2017/2018 -- network flow data with attack labels.

Option B: Generate from real schemas
- Use the Elastic integration sample events as templates.
- For each sample event type (e.g., Palo Alto firewall allow, AWS API Gateway GET, Okta auth success), write a generator that produces realistic variations: randomize IPs, timestamps, usernames, paths, ports.
- This is better than process1's synthetic data because the log structure matches real vendor formats.
- Generate 500k-1M normal sessions this way.

Option C: Export from a real SIEM
- If you have access to a Splunk/Sentinel/ELK instance, export a week of normal operational logs.
- Filter out known incidents. Everything else is "normal."
- This is the best option if available.

**Output of this step:** Enough normal sessions added to `pretrain_sessions.jsonl` to reach at least 500k sessions. Normal sessions added to `finetune_sessions.jsonl` as well (aim for 70% normal, 30% attack ratio).

---

## Step 6: Expand canonical patterns and special tokens

**What:** The process1 regex patterns are Windows-centric. Expand them for the real data you now have.

**Add these canonical patterns:**

```
Linux paths:         /usr/bin/*, /etc/*, /var/log/*           -> [UNIX_PATH]
Cloud ARNs:          arn:aws:*:*:*                            -> [CLOUD_ARN]
Cloud resource IDs:  i-0abc1234, sg-abc123, vpc-abc123        -> [CLOUD_RESOURCE]
Container IDs:       64-char hex (docker container IDs)        -> [CONTAINER_ID]
MAC addresses:       AA:BB:CC:DD:EE:FF                        -> [MAC_ADDR]
Email addresses:     user@domain.com                           -> [EMAIL]
Base64 blobs:        long base64 strings (>20 chars)           -> [BASE64]
GUIDs:               xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx      -> [GUID]
```

**Add these special tokens to the tokenizer:**

```
[EVT_SEP]       -- separates events within a session
[NORMAL]        -- class label token (used in Phase 2 for the normal/benign class)
```

**Update the threat categories:**

```
0:  normal            <-- NEW: explicit benign class
1:  malware
2:  ransomware
3:  c2
4:  lateral_movement
5:  credential_theft
6:  exfiltration
7:  phishing
8:  brute_force
9:  priv_esc
10: insider
11: web_attack
12: dos
13: policy_violation
14: recon
15: defense_evasion   <-- NEW: covers rootkits, timestomping, log clearing
```

That is 16 classes total. Update `num_threat_categories` in BERTConfig to 16.

**Output of this step:** Updated canonical pattern list, updated special token list, updated threat category mapping.

---

## Step 7: Retrain the tokenizer

**What:** The BPE tokenizer from process1 was trained on synthetic data. The merges it learned are meaningless for real logs. Retrain it from scratch on your normalized real data.

**How:**

1. Sample 50k-100k sessions from `pretrain_sessions.jsonl`
2. Run canonicalization on each (replace IPs, paths, etc. with canonical tokens)
3. Train BPE on the canonicalized text
4. Keep vocab_size at 8192 (or increase to 16384 if the real data has more diverse vocabulary)
5. Save as `security_tokenizer_v2.json`

**Verify:**
- Encode a few real sessions and check that the token count is reasonable (not too many [UNK] tokens)
- Check that security-relevant terms (event_type values, field names, common process names) are in the vocabulary as single tokens or short subwords
- Check average tokens per session. If most sessions exceed 512 tokens after encoding, you need to either increase max_seq_len or summarize events more aggressively in the normalizer

**Output of this step:** `security_tokenizer_v2.json`

---

## Step 8: Update the model architecture

**What:** Small changes to the BERT model from process1.

**Changes:**

1. Increase max_seq_len from 128 to 512. This means the positional embedding table grows from 128x256 to 512x256. Memory usage for attention goes up 16x (512^2 vs 128^2), but a T4 with 16GB can handle batch_size=16 at seq_len=512 comfortably.

2. Change num_threat_categories from 14 to 16 (added normal and defense_evasion).

3. Remove num_segments and seg_emb. You are not using segment embeddings. Removing them is cleaner than having dead parameters.

4. Consider adding a [EVT_SEP] positional reset or event-level positional encoding. Right now positions are absolute (0 to 511). An alternative: reset position counter at each [EVT_SEP] and add an event-index embedding. This tells the model "this is the 3rd token in the 5th event" rather than just "this is position 47." This is optional but would help with longer sessions.

5. Everything else stays the same: 6 layers, 8 heads, hidden 256, ff 1024, pre-norm, GELU.

**Output of this step:** Updated BERTConfig and SecurityBERT class.

---

## Step 9: Phase 1 -- MLM pretraining on real data

**What:** Train the encoder to understand real log patterns using masked language modeling.

**Data:** `pretrain_sessions.jsonl` -- normal sessions only, no labels needed.

**Training setup:**
- Same as process1 but with updated tokenizer and max_seq_len=512
- Batch size: 16 (reduced from 64 because sequences are 4x longer)
- Learning rate: 1e-4 with warmup
- Epochs: 3-5
- Span masking at 15% (same as process1)
- Eval on 10% held-out validation split
- Save best checkpoint by validation loss

**What to watch for:**
- Validation loss should decrease steadily. If it plateaus early, the data might not have enough variety.
- If training is too slow, use gradient accumulation (effective_batch_size = batch_size x accumulation_steps).

**Output of this step:** `bert_v2_phase1_best.pt`

---

## Step 10: Phase 2 -- Supervised fine-tuning on labeled data

**What:** Attach classification heads and train on labeled attack + normal sessions.

**Data:** `finetune_sessions.jsonl` -- labeled sessions, 70% normal / 30% attack. Split into 80% train, 20% validation.

**Training setup:**
- Load Phase 1 weights
- Differential learning rates: encoder at 2e-5, classification heads at 2e-4
- Batch size: 16
- Epochs: 5-10
- Use class weights in the loss function to handle imbalance between threat categories. Some categories (credential_theft) will have thousands of sessions from the Splunk data. Others (dos, insider) might have very few. Weight the loss inversely proportional to class frequency.
- Use focal loss instead of plain cross entropy for the threat head. This helps the model focus on hard-to-classify examples rather than getting lazy on the easy majority class.

**Classification heads (same as process1 but updated):**
- threat_head: 256 -> 16 (was 14)
- severity_head: 256 -> 5 (same)
- confidence_head: 256 -> 4 (same)
- tp_head: 256 -> 1 binary (same)
- surface_head: 256 -> 8 multi-label (same)

**Output of this step:** `bert_v2_phase2_best.pt`

---

## Step 11: Evaluate properly

**What:** Measure the model with metrics that matter for a SOC use case.

**Metrics to compute on the validation set:**

For anomaly detection (Phase 1 output):
- ROC curve and AUC score
- Precision-recall curve
- False positive rate at 95% and 99% detection rate
- Optimal threshold by F1

For classification (Phase 2 output):
- Per-class precision, recall, F1
- Macro and weighted F1
- Confusion matrix (which threat categories get confused with each other?)
- True positive rate vs false positive rate at the chosen operating threshold

**What good looks like:**
- Anomaly AUC > 0.95
- Per-class F1 > 0.80 for major threat categories
- False positive rate < 5% at 90%+ detection rate

If numbers are bad, the most likely cause is data quality (not enough variety in normal data, or attack sessions look too different from the normalized format the model trained on). Go back to Step 5 and improve the data before tweaking the model.

**Output of this step:** An evaluation report with all metrics. Save as `evaluation_report.json` and print a summary.

---

## Step 12: Calibrate anomaly threshold on real data

**What:** Set the threshold that separates normal from anomalous sessions.

**How:**
1. Run the trained model on 5,000+ normal validation sessions. Collect MLM loss scores.
2. Run on all attack validation sessions. Collect MLM loss scores.
3. Plot both distributions.
4. Pick threshold that maximizes F1 (or pick based on your tolerance for false positives vs missed detections).
5. Save threshold, mean, std to config file.

**Important:** This threshold will drift as your environment changes. In production, recalibrate monthly or when major infrastructure changes happen.

**Output of this step:** Updated `detection_config.json` with calibrated threshold.

---

## Step 13: Build the inference pipeline

**What:** A clean function that takes a raw log (in any supported format) and returns a detection result.

**The pipeline:**

```
raw log (any format)
    |
    v
detect_format() -- figure out if it is XML, JSON, CSV, syslog
    |
    v
parse() -- call the right parser, get a list of unified event dicts
    |
    v
window() -- group into sessions (or add to an existing session buffer)
    |
    v
normalize_to_text() -- flatten each session to model input text
    |
    v
tokenize() -- run canonical patterns + BPE
    |
    v
model.forward() -- get anomaly score + classification
    |
    v
result dict: {is_anomaly, score, threat_category, severity, confidence, ...}
```

For streaming use, the windowing step needs to be stateful. It holds a buffer of recent events per (host, user) pair. When a new event arrives, it gets added to the buffer. When the buffer hits 5 minutes or a max event count, the session is flushed to the model.

**Output of this step:** A `SecurityBERTDetector` class with a `detect(raw_log: str) -> dict` method.

---

## Step 14: Package for deployment

**What:** Bundle everything needed to run inference.

**The bundle:**
```
security_bert_v2/
    model_phase1.pt          -- Phase 1 weights (for anomaly scoring)
    model_phase2.pt          -- Phase 2 weights (for classification)
    tokenizer.json           -- trained BPE tokenizer
    config.json              -- model config, threshold, calibration stats
    parsers/                 -- log parser modules
    detector.py              -- the inference class
    requirements.txt         -- torch, numpy, etc.
```

**Output of this step:** A deployable directory or package.

---

## Summary: The work in order

| Step | What | Depends on | Output |
|------|------|-----------|--------|
| 1 | Define unified event schema | Nothing | Schema definition + to_model_text() |
| 2 | Write log parsers | Step 1 | Parser functions for XML, JSON, CSV, EVTX |
| 3 | Run parsers on all raw data | Steps 1-2 | normalized_events.jsonl |
| 4 | Session windowing | Step 3 | pretrain_sessions.jsonl, finetune_sessions.jsonl |
| 5 | Get more normal data | Step 4 | Expanded pretrain_sessions.jsonl |
| 6 | Expand canonical patterns | Nothing (can do in parallel with 1-5) | Updated regex list + token list |
| 7 | Retrain tokenizer | Steps 4-6 | security_tokenizer_v2.json |
| 8 | Update model architecture | Step 6 | Updated BERTConfig + SecurityBERT |
| 9 | Phase 1 MLM pretraining | Steps 7-8 | bert_v2_phase1_best.pt |
| 10 | Phase 2 fine-tuning | Step 9 | bert_v2_phase2_best.pt |
| 11 | Evaluate | Step 10 | evaluation_report.json |
| 12 | Calibrate threshold | Steps 9-10 | detection_config.json |
| 13 | Build inference pipeline | Steps 2, 10, 12 | SecurityBERTDetector class |
| 14 | Package | Step 13 | Deployable bundle |

Steps 1-5 are data engineering. Steps 6-8 are model setup. Steps 9-10 are training. Steps 11-14 are evaluation and deployment. The data engineering is the hardest and most important part. The model itself is mostly done from process1.
