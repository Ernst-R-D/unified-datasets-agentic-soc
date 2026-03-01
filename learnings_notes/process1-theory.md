# SecurityBERT -- Theory and Dataset Approach

---

## Part 1: How the Model Works (Plain English)

### The Encoder -- the brain of the model

The encoder reads the entire log session at once, in both directions. Every token can see every other token. After 6 layers of this, each token position holds a rich summary of what that token means in the context of the full session.

Imagine you are reading a sentence with a word blanked out:

```
"The cat sat on the ___"
```

You know the answer is probably "mat" or "floor" because you read the words around it. The encoder does exactly this, but for log events. It reads the full session and builds an understanding of what belongs and what does not.

The [CLS] token at position 0 is special. It has no meaning of its own. Its only job is to absorb information from every other token through 6 rounds of attention. By the end, it holds a single vector that summarizes the entire session. Think of it as a compressed fingerprint of the whole log.


### Phase 1 -- MLM (teaching the encoder what normal looks like)

You take a normal log session:

```
[SESSION_START] user=jsmith [USER_LOGIN] auth=password [FILE_READ] [USER_LOGOUT] [SESSION_END]
```

You hide 15% of the tokens:

```
[SESSION_START] user=jsmith [MASK] auth=password [FILE_READ] [MASK] [SESSION_END]
```

You ask the model: what were the hidden tokens?

The encoder processes the whole thing. At each [MASK] position, the MLM head (a small feedforward layer) takes that position's hidden vector and says "I think this was [USER_LOGIN]" or "I think this was [USER_LOGOUT]."

If the model guesses correctly, the loss is low. If it guesses wrong, the loss is high, and the weights get updated.

After 900k sessions of this, the encoder has learned the grammar of normal logs. It knows that after a login you expect file reads or network connections, not registry writes from cmd.exe. It knows that office users do not spawn powershell from outlook.

This is why anomaly detection works after Phase 1 alone. If you give the trained model an attack session and mask some tokens, it will struggle to predict them because the sequence does not follow normal patterns. High loss = anomaly.


### Phase 2 -- Classification heads (teaching the encoder to name threats)

Now you keep the encoder mostly frozen (low learning rate so you do not destroy what it learned) and attach small linear layers on top of the [CLS] vector.

The [CLS] vector is 256 numbers. Each classification head is basically:

```
threat_head:    take 256 numbers in, produce 14 numbers out (one per threat category)
severity_head:  take 256 numbers in, produce 5 numbers out (critical/high/medium/low/info)
tp_head:        take 256 numbers in, produce 1 number out (true positive or not)
```

The highest number wins. If the threat head outputs:

```
[0.1, 0.05, 0.8, 0.02, ...]
 malware ransomware c2  lateral...
```

Then the model says "this is C2 beaconing" because index 2 (c2) has the highest score.

You train this on 100k labeled sessions where you know the answers. The classification heads learn to read the [CLS] fingerprint and map it to the right labels.


### Why two phases instead of one

Phase 1 uses 900k unlabeled normal sessions. No labels needed. Just raw logs. These are cheap and plentiful -- any SIEM has millions of them.

Phase 2 uses 100k labeled sessions. These are expensive -- a human analyst had to look at each one and say "this is ransomware" or "this is normal." You will never have as many labeled samples as unlabeled ones.

By doing Phase 1 first, the encoder already understands log structure before it ever sees a label. Phase 2 just teaches it the last mile -- mapping that understanding to threat names. Without Phase 1, the encoder would have to learn both how to read logs AND how to classify threats from just 100k examples, which is much harder.


### Do we need a decoder?

No. A decoder is for generating text (like GPT writing a response). Our task is classification -- take a log session, output a label. The encoder gives us the [CLS] vector, the classification heads give us the answer. There is nothing to generate, nothing to decode.

The MLM head in Phase 1 might look like a decoder, but it is not. It is a simple feedforward layer that projects each position's hidden state back to vocab size. It operates independently on each position with no autoregressive generation.

---

## Part 2: The Raw Dataset -- What We Have

Location: `/Users/juhiechandra/Documents/UnifiedSecOps-V1/synthesizer/data/raw_logs/`

### Inventory

| Source | Format | Content | Count |
|--------|--------|---------|-------|
| Elastic integrations (JSON) | Structured JSON per event | Sample events from 257 data streams across EDR, firewall, cloud, IAM, SaaS, email, SIEM, ticketing | ~5,656 sample events |
| Splunk attack logs | Raw Windows Event XML (.log) | Attack technique reproductions, each file named by MITRE TTP (T1003, T1021, T1055, etc.) | 51 files, ~1.07M event lines |
| Sentinel | CSV (schema + ingested logs) | ASIM-normalized logs from Cisco Meraki, CrowdStrike, Palo Alto, Trend Micro, VMware CB, Linux auditd, etc. | 76 ingested log files, 23 schemas |
| EDR / EVTX | Binary Windows Event Log (.evtx) | Real attack reproductions: credential access, C2, automated testing tools | 30 evtx files |
| Mordor | YAML metadata index | Security dataset catalog with MITRE mappings, references to downloadable attack datasets | Metadata only (no raw events yet) |
| Sigma | JSON | Detection rule definitions in Sigma format | Rule definitions |
| Wazuh | Directories | Decoder and rule definitions | Rule definitions |
| Detection rules | JSON/TOML | Elastic detection rules with test data | Rule definitions |
| CrowdStrike FDR | JSON schema | FDR (Falcon Data Replicator) field schemas | Schema only |

### What kind of data is this -- normal or attack?

It is almost entirely attack data and detection-related samples. Here is the breakdown:

**Mostly attack/alert data:**
- Splunk logs (1.07M lines): All 51 files are named `attack_techniques_T1xxx_...`. These are attack reproductions from tools like Atomic Red Team. This is pure attack data.
- EDR EVTX files (30 files): Named `Credential_Access_*`, `Command_and_Control_*`, `AutomatedTestingTools_*`. These are attack reproductions.
- Mordor: A catalog of attack datasets mapped to MITRE TTPs.
- Elastic alert streams: CrowdStrike alerts, SentinelOne alerts, Splunk alerts, etc.

**Sample/reference data (small, mixed):**
- Elastic integration samples (~5,656 events): These are sample events from Elastic integration packages. They include normal operational logs (AWS API Gateway, firewall traffic, SaaS audit logs) and some alert events. These are not bulk data -- they are one or a few samples per data stream type. Their value is showing the FORMAT and SCHEMA of each log source, not providing training volume.
- Sentinel CSVs: ASIM-normalized log samples. Mix of auth events, network events, etc. Small samples.

**Not log data (metadata/rules):**
- Sigma rules, Wazuh decoders, Elastic detection rules: These define how to detect threats, not actual log events. Useful for understanding what patterns matter, but not training data.

### Key finding

You have a lot of attack data and very little normal data. This is the opposite of what you need for Phase 1 (MLM pretraining), which requires large volumes of normal logs. However, the attack data is exactly what you need for Phase 2 (fine-tuning), and the format samples from Elastic integrations are exactly what you need to build a log-agnostic normalizer.

---

## Part 3: Making the Model Log-Agnostic -- The Approach

The core problem is that real SIEM logs come in wildly different formats:

```
Windows Event XML:
<Event><System><EventID>4688</EventID>...</System><EventData><Data Name='CommandLine'>ntdsutil...</Data></EventData></Event>

Elastic JSON:
{"@timestamp":"2023-11-03T18:00:22Z","crowdstrike":{"alert":{"cmdline":"C:\\Users\\...","severity":4}}}

Sentinel CSV (ASIM):
TenantId,TimeGenerated,Computer,RawData,...
1a0e2567...,6/15/2023 12:09:31,...,<134>1 1686830953 CDSAPF501 events type=disassociation...

Palo Alto firewall JSON:
{"destination":{"domain":"lorexx.cn","ip":"175.16.199.1","port":80},"source":{"ip":"10.0.0.1"}}

Raw syslog:
<134>1 1686830953.736 CDSAPF501 events type=disassociation radio='1' vap='3' client_mac='AA:BB:CC:DD:EE:FF'
```

The model cannot learn separate grammars for every vendor. We need a normalization layer that converts any log format into a common representation before feeding it to the model.

### The approach: Unified Event Schema (UES)

The idea is simple. Before any log hits the model, it passes through a normalizer that extracts a fixed set of fields and produces a flat text representation. The model only ever sees the normalized form.

#### Step 1: Define the unified schema

Every log event, regardless of source, gets mapped to these core fields:

```
timestamp       -- when it happened (ISO 8601)
event_type      -- what happened (process_create, file_write, net_conn, auth_success, auth_fail, dns_query, alert, etc.)
source_ip       -- who initiated
dest_ip         -- who received
source_host     -- hostname of origin
user            -- user identity
process_name    -- process involved
parent_process  -- parent process (if applicable)
command_line    -- command line (if applicable)
file_path       -- file path (if applicable)
dest_port       -- destination port
protocol        -- network protocol
severity        -- vendor-reported severity (if any)
log_source      -- which vendor/product (crowdstrike, panw, sentinel, sysmon, etc.)
raw_extra       -- anything that does not fit above, truncated
```

Not every log will have every field. That is fine. Missing fields become empty.

#### Step 2: Write per-source parsers

Each log format needs a parser function that extracts the unified fields. Based on what is in the dataset:

```
Parser needed for:
  - Windows Event XML (Splunk .log files, EVTX)    --> biggest volume, 1M+ events
  - Elastic integration JSON (all packages)          --> ~5,600 events, many formats
  - Sentinel ASIM CSV                                --> 76 files
  - Syslog (raw text with facility/severity codes)   --> embedded in Sentinel CSVs
  - CrowdStrike Falcon alerts (JSON)                 --> structured alerts
  - Palo Alto PAN-OS (JSON)                           --> firewall events
  - AWS CloudTrail/GuardDuty (JSON)                   --> cloud events
```

Each parser reads its native format and outputs a dict with the unified fields.

#### Step 3: Convert unified dict to model input text

The normalized dict gets flattened to a text string that the tokenizer can process:

```
Input (raw CrowdStrike alert JSON):
{"crowdstrike":{"alert":{"cmdline":"C:\\Users\\...pfSense...","severity":4,"tactic":"Execution","technique":"T1204"}}}

Normalized text for model:
[TIMESTAMP] event_type=alert log_source=crowdstrike user=yuvraj.mahajan source_host=elastic-agent-43429 process_name=[WIN_PATH] command_line=[WIN_PATH] severity=4 mitre=[MITRE_TID]
```

The canonical pattern regex from process1 (IP, path, hash, LOLBin, etc.) runs on this normalized text, collapsing entities into tokens. Then BPE runs on the rest.

This way the model sees a consistent vocabulary regardless of whether the original log was XML, JSON, CSV, or syslog.

#### Step 4: Separate normal vs attack data for the two training phases

Based on what is in the dataset:

**For Phase 2 (fine-tuning -- labeled attack + normal data):**
- Splunk attack logs (1.07M events across 51 MITRE techniques): These are your primary attack dataset. The filename gives you the MITRE technique ID (T1003, T1021, etc.), which maps directly to threat categories. Parse the Windows Event XML, normalize, and label with the MITRE category.
- EDR EVTX files (30 files): Same approach -- parse with python-evtx library, normalize, label by filename category.
- Elastic alert events (~67 events): Small but useful. These are vendor-detected alerts with severity and category info embedded in the JSON.

**For Phase 1 (MLM pretraining -- bulk normal data):**
- This is where you have a gap. The dataset is attack-heavy. You need normal operational logs. Options:
  a. Use the Elastic integration sample events as templates and synthetically generate realistic normal traffic at scale (hundreds of thousands of events) using the formats you now understand from the real samples. This is better than the current approach in process1 because the templates would be based on real log schemas, not invented session formats.
  b. Export normal logs from your own SIEM if you have access to one. Even a week of normal operations from a small environment gives you millions of events.
  c. Use public datasets: LANL unified host/network dataset, CICIDS, or BETH dataset contain large volumes of normal enterprise traffic.

**For the "normal" class in Phase 2:**
- The Elastic integration samples that are NOT alerts (firewall allows, normal auth events, SaaS audit logs, cloud API calls) can be labeled as normal. There are about 5,500 of these. Not enough volume on their own but useful as seeds for augmentation.

#### Step 5: Session windowing

Individual events are not useful on their own. The model expects sessions (sequences of related events). Group normalized events into sessions by:

- Same user + same host + events within a 5-minute sliding window
- OR same process tree (parent-child process chain)
- OR same network connection tuple (src_ip:src_port -> dst_ip:dst_port)

For the Splunk attack data, events in the same .log file that share the same Computer and SubjectUserName within a time window form a natural session.

#### Step 6: Retrain everything on normalized data

1. Retrain the BPE tokenizer on normalized real events (not synthetic templates)
2. Phase 1: MLM pretrain on bulk normal sessions
3. Phase 2: Fine-tune on labeled attack + normal sessions
4. Recalibrate anomaly threshold on held-out normal validation set

### What makes this log-agnostic

The model never sees raw vendor-specific formats. It only sees normalized text like:

```
event_type=process_create log_source=sysmon user=admin process_name=[LOLBIN] parent_process=cmd.exe command_line=[WIN_PATH]
```

Whether the original was a Sysmon event, CrowdStrike detection, or Palo Alto log does not matter. The normalizer absorbed the vendor differences. The model learns security semantics, not log formats.

The `log_source` field is still included so the model can learn that "a CrowdStrike alert for severity 4 means something different than a firewall deny" -- but the core event structure is always the same.

---

## Part 4: Immediate Action Plan

### What to do now (in order)

1. Write parsers for Windows Event XML (covers the 1.07M Splunk events, biggest dataset).
2. Write parsers for Elastic integration JSON (covers all the sample events).
3. Write a session windowing function.
4. Build the Phase 2 labeled dataset from Splunk attack logs + EVTX files. Label by MITRE technique from filenames.
5. Build a normal dataset. Either export from a real SIEM, use public datasets (LANL, BETH), or generate from Elastic sample formats at scale.
6. Retrain tokenizer, Phase 1, Phase 2 on normalized data.
7. Add a proper "normal/benign" class (class 14 or class 0) instead of overloading policy_violation.
8. Add per-class evaluation metrics (precision, recall, F1, confusion matrix).
9. Increase max_seq_len to 512.

### What we can use from process1 as-is

- The BERT architecture (SecurityBERT class) -- sound, just needs max_seq_len increase
- The canonical pattern regexes -- good, need expansion for Linux/cloud patterns
- The custom BPE tokenizer class -- good, just needs retraining on real data
- The two-phase training loop -- good
- The anomaly scoring function -- good concept, needs recalibration on real data
- The classification heads -- good, need one more class for "normal"

### What needs to be rewritten

- Data generation (replace synthetic template generators with real log parsers + normalizer)
- Tokenizer training data (real normalized events instead of synthetic sessions)
- Evaluation code (add precision/recall/F1/confusion matrix, not just accuracy)
- Anomaly threshold calibration (on real normal data, larger sample, periodic recalibration)
