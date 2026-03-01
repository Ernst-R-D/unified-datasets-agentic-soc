"""
Parse all downloaded raw log datasets into unified JSONL format.

Parses:
1. SecRepo Zeek conn.log, dns.log, http.log (normal network traffic)
2. SecRepo auth.log (SSH auth logs)
3. OTRF Security-Datasets (Windows event logs in JSON, attack + benign context)
4. Elastic integration samples from raw_logs (JSON, mixed)
5. Splunk attack logs from raw_logs (Windows Event XML)
6. Sentinel ingested logs from raw_logs (CSV)

Output: datasets/parsed/*.jsonl
"""

import json
import gzip
import os
import re
import sys
import csv
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

BASE = Path(__file__).parent
RAW_LOGS = Path("/Users/juhiechandra/Documents/UnifiedSecOps-V1/synthesizer/data/raw_logs")
NORMAL_LOGS = BASE / "normal_logs"
PARSED = BASE / "parsed"
PARSED.mkdir(exist_ok=True)

stats = Counter()


def write_jsonl(filepath, records):
    with open(filepath, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"  Wrote {len(records):,} records -> {filepath.name}")
    stats[filepath.name] = len(records)


# ---------------------------------------------------------------------------
# 1. SecRepo Zeek conn.log -> network connection events
# ---------------------------------------------------------------------------
def parse_zeek_conn():
    gz_path = NORMAL_LOGS / "secrepo" / "conn.log.gz"
    if not gz_path.exists():
        print("SKIP: conn.log.gz not found")
        return
    print("Parsing Zeek conn.log...")
    records = []
    with gzip.open(gz_path, "rt", errors="replace") as f:
        for i, line in enumerate(f):
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split("\t")
            if len(parts) < 8:
                continue
            rec = {
                "timestamp": parts[0],
                "event_type": "net_connect",
                "log_source": "zeek",
                "source_ip": parts[2] if len(parts) > 2 else "",
                "source_port": parts[3] if len(parts) > 3 else "",
                "dest_ip": parts[4] if len(parts) > 4 else "",
                "dest_port": parts[5] if len(parts) > 5 else "",
                "protocol": parts[6] if len(parts) > 6 else "",
                "service": parts[7] if len(parts) > 7 else "",
                "label": "normal",
            }
            records.append(rec)
            if len(records) >= 1_000_000:
                break
    write_jsonl(PARSED / "zeek_conn.jsonl", records)


# ---------------------------------------------------------------------------
# 2. SecRepo Zeek dns.log
# ---------------------------------------------------------------------------
def parse_zeek_dns():
    gz_path = NORMAL_LOGS / "secrepo" / "dns.log.gz"
    if not gz_path.exists():
        print("SKIP: dns.log.gz not found")
        return
    print("Parsing Zeek dns.log...")
    records = []
    with gzip.open(gz_path, "rt", errors="replace") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split("\t")
            if len(parts) < 10:
                continue
            rec = {
                "timestamp": parts[0],
                "event_type": "dns_query",
                "log_source": "zeek",
                "source_ip": parts[2] if len(parts) > 2 else "",
                "source_port": parts[3] if len(parts) > 3 else "",
                "dest_ip": parts[4] if len(parts) > 4 else "",
                "dest_port": parts[5] if len(parts) > 5 else "",
                "protocol": parts[6] if len(parts) > 6 else "",
                "query": parts[8] if len(parts) > 8 else "",
                "query_type": parts[12] if len(parts) > 12 else "",
                "response_code": parts[14] if len(parts) > 14 else "",
                "label": "normal",
            }
            records.append(rec)
    write_jsonl(PARSED / "zeek_dns.jsonl", records)


# ---------------------------------------------------------------------------
# 3. SecRepo Zeek http.log
# ---------------------------------------------------------------------------
def parse_zeek_http():
    gz_path = NORMAL_LOGS / "secrepo" / "http.log.gz"
    if not gz_path.exists():
        print("SKIP: http.log.gz not found")
        return
    print("Parsing Zeek http.log...")
    records = []
    with gzip.open(gz_path, "rt", errors="replace") as f:
        for i, line in enumerate(f):
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split("\t")
            if len(parts) < 10:
                continue
            rec = {
                "timestamp": parts[0],
                "event_type": "net_connect",
                "log_source": "zeek_http",
                "source_ip": parts[2] if len(parts) > 2 else "",
                "source_port": parts[3] if len(parts) > 3 else "",
                "dest_ip": parts[4] if len(parts) > 4 else "",
                "dest_port": parts[5] if len(parts) > 5 else "",
                "method": parts[7] if len(parts) > 7 else "",
                "host": parts[8] if len(parts) > 8 else "",
                "uri": parts[9] if len(parts) > 9 else "",
                "status_code": parts[15] if len(parts) > 15 else "",
                "user_agent": parts[12] if len(parts) > 12 else "",
                "label": "normal",
            }
            records.append(rec)
            if len(records) >= 1_000_000:
                break
    write_jsonl(PARSED / "zeek_http.jsonl", records)


# ---------------------------------------------------------------------------
# 4. SecRepo auth.log (SSH)
# ---------------------------------------------------------------------------
def parse_auth_log():
    gz_path = NORMAL_LOGS / "secrepo" / "auth.log.gz"
    if not gz_path.exists():
        print("SKIP: auth.log.gz not found")
        return
    print("Parsing auth.log...")
    records = []
    with gzip.open(gz_path, "rt", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Determine event type from content
            if "Accepted" in line:
                evt = "auth_success"
            elif "Failed" in line:
                evt = "auth_fail"
            elif "session opened" in line:
                evt = "auth_success"
            elif "session closed" in line:
                evt = "auth_logout"
            else:
                evt = "other"

            # Extract IP if present
            ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
            user_match = re.search(r"for\s+(?:invalid\s+user\s+)?(\S+)", line)

            rec = {
                "timestamp": line[:15] if len(line) > 15 else "",
                "event_type": evt,
                "log_source": "sshd",
                "source_ip": ip_match.group(1) if ip_match else "",
                "user": user_match.group(1) if user_match else "",
                "raw": line[:300],
                "label": "normal",
            }
            records.append(rec)
    write_jsonl(PARSED / "ssh_auth.jsonl", records)


# ---------------------------------------------------------------------------
# 5. OTRF Security-Datasets (Windows event logs in ZIP -> JSON)
# ---------------------------------------------------------------------------
def parse_otrf():
    sd_path = NORMAL_LOGS / "Security-Datasets" / "datasets"
    if not sd_path.exists():
        print("SKIP: Security-Datasets not found")
        return
    print("Parsing OTRF Security-Datasets...")
    records = []
    zip_files = list(sd_path.rglob("*.zip"))
    print(f"  Found {len(zip_files)} zip files")

    for zf_path in zip_files:
        # Extract MITRE category from path
        parts = zf_path.relative_to(sd_path).parts
        # e.g. atomic/windows/credential_access/host/file.zip
        platform = parts[1] if len(parts) > 1 else "unknown"
        category = parts[2] if len(parts) > 2 else "unknown"
        mitre_label = category  # credential_access, lateral_movement, etc.

        try:
            with zipfile.ZipFile(zf_path, "r") as zf:
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    with zf.open(name) as jf:
                        for line in jf:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                evt = json.loads(line)
                            except json.JSONDecodeError:
                                continue

                            # Extract key fields from Windows event JSON
                            rec = {
                                "timestamp": evt.get("@timestamp", evt.get("Timestamp", "")),
                                "event_type": _map_windows_event_type(evt),
                                "log_source": f"otrf_{platform}",
                                "source_host": evt.get("Hostname", evt.get("host", {}).get("name", "") if isinstance(evt.get("host"), dict) else ""),
                                "user": _extract_user(evt),
                                "process_name": _extract_field(evt, ["ProcessName", "NewProcessName", "Image", "process_name"]),
                                "parent_process": _extract_field(evt, ["ParentProcessName", "ParentImage", "ParentCommandLine"]),
                                "command_line": _extract_field(evt, ["CommandLine", "ProcessCommandLine"]),
                                "event_id": str(evt.get("EventID", "")),
                                "source_ip": _extract_field(evt, ["IpAddress", "SourceAddress", "SourceIp", "src_ip"]),
                                "dest_ip": _extract_field(evt, ["DestinationIp", "DestinationAddress", "dst_ip"]),
                                "dest_port": _extract_field(evt, ["DestinationPort", "dst_port"]),
                                "attack_category": mitre_label,
                                "platform": platform,
                                "label": "attack",
                                "source_file": zf_path.name,
                            }
                            # Filter empty values
                            rec = {k: v for k, v in rec.items() if v}
                            rec.setdefault("label", "attack")
                            records.append(rec)

                            if len(records) % 100_000 == 0:
                                print(f"    {len(records):,} events parsed...")
        except (zipfile.BadZipFile, Exception) as e:
            continue

    write_jsonl(PARSED / "otrf_windows_events.jsonl", records)


def _map_windows_event_type(evt):
    eid = str(evt.get("EventID", ""))
    channel = evt.get("Channel", "")
    mapping = {
        "1": "process_create", "5": "process_terminate",
        "3": "net_connect", "22": "dns_query",
        "11": "file_write", "23": "file_delete",
        "13": "registry_write", "12": "registry_write",
        "4688": "process_create", "4689": "process_terminate",
        "4624": "auth_success", "4625": "auth_fail",
        "4634": "auth_logout", "4648": "auth_success",
        "4663": "file_read", "4657": "registry_write",
        "4672": "priv_esc", "4720": "user_create",
        "4732": "group_modify", "5156": "net_connect",
        "7045": "service_create",
    }
    return mapping.get(eid, "other")


def _extract_user(evt):
    for key in ["SubjectUserName", "TargetUserName", "User", "user", "UserName"]:
        val = evt.get(key, "")
        if val and val != "-" and val != "SYSTEM":
            return str(val)
    return ""


def _extract_field(evt, keys):
    for k in keys:
        val = evt.get(k, "")
        if val and val != "-":
            return str(val)[:500]
    return ""


# ---------------------------------------------------------------------------
# 6. Elastic integration samples from raw_logs
# ---------------------------------------------------------------------------
def parse_elastic_samples():
    elastic_dir = RAW_LOGS / "elastic"
    if not elastic_dir.exists():
        print("SKIP: Elastic raw_logs not found")
        return
    print("Parsing Elastic integration samples...")
    records = []

    for json_path in elastic_dir.rglob("*.json"):
        try:
            with open(json_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, Exception):
            continue

        if not isinstance(data, dict) or "events" not in data:
            continue

        package = data.get("package", "unknown")
        category = json_path.parent.name  # edr, firewall, cloud, etc.

        for evt_wrapper in data["events"]:
            sample = evt_wrapper.get("sample_event", evt_wrapper)
            ds = evt_wrapper.get("data_stream", "")

            is_alert = any(x in ds.lower() for x in ["alert", "detection", "incident"])

            rec = {
                "timestamp": sample.get("@timestamp", ""),
                "event_type": _classify_elastic_event(sample, ds),
                "log_source": f"elastic_{package}",
                "data_stream": ds,
                "category": category,
                "label": "alert" if is_alert else "normal",
            }

            # Flatten common ECS fields
            _flatten_ecs(sample, rec)

            records.append(rec)

    write_jsonl(PARSED / "elastic_samples.jsonl", records)


def _classify_elastic_event(evt, data_stream):
    ds_lower = data_stream.lower()
    if "alert" in ds_lower or "detection" in ds_lower:
        return "alert"
    if "auth" in ds_lower or "login" in ds_lower or "logon" in ds_lower:
        return "auth_success"
    if "dns" in ds_lower:
        return "dns_query"
    if "firewall" in ds_lower or "panos" in ds_lower:
        return "net_connect"
    if "process" in ds_lower:
        return "process_create"
    if "file" in ds_lower:
        return "file_write"
    if "audit" in ds_lower:
        return "other"
    return "other"


def _flatten_ecs(evt, rec):
    """Walk nested dict and extract common ECS fields."""
    flat = {}
    _flatten_dict(evt, flat, "")

    ecs_map = {
        "source.ip": "source_ip",
        "destination.ip": "dest_ip",
        "destination.port": "dest_port",
        "destination.domain": "dest_domain",
        "host.name": "source_host",
        "user.name": "user",
        "process.name": "process_name",
        "process.pid": "pid",
        "process.command_line": "command_line",
        "process.parent.name": "parent_process",
        "event.action": "action",
        "event.severity": "severity",
        "event.category": "event_category",
        "network.protocol": "protocol",
        "url.full": "url",
        "file.path": "file_path",
    }

    for ecs_key, our_key in ecs_map.items():
        if ecs_key in flat and flat[ecs_key]:
            rec[our_key] = str(flat[ecs_key])[:500]


def _flatten_dict(d, out, prefix):
    if not isinstance(d, dict):
        return
    for k, v in d.items():
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            _flatten_dict(v, out, full_key)
        elif isinstance(v, list):
            continue
        else:
            out[full_key] = v


# ---------------------------------------------------------------------------
# 7. Splunk attack logs (Windows Event XML)
# ---------------------------------------------------------------------------
def parse_splunk_attack_logs():
    splunk_dir = RAW_LOGS / "splunk"
    if not splunk_dir.exists():
        print("SKIP: Splunk raw_logs not found")
        return
    print("Parsing Splunk attack logs (Windows Event XML)...")
    records = []

    for log_path in sorted(splunk_dir.glob("*.log")):
        # Extract MITRE technique from filename
        # e.g. attack_techniques_T1003.003_atomic_red_team_4688_windows-security.log
        mitre_match = re.search(r"(T\d{4}(?:\.\d{3})?)", log_path.name)
        mitre_id = mitre_match.group(1) if mitre_match else ""
        category = _mitre_to_category(mitre_id)

        with open(log_path, "r", errors="replace") as f:
            content = f.read()

        # Split on <Event> tags
        events = re.findall(r"<Event[^>]*>.*?</Event>", content, re.DOTALL)

        for evt_xml in events:
            rec = _parse_windows_xml_event(evt_xml)
            rec["log_source"] = "splunk_attack"
            rec["mitre_technique"] = mitre_id
            rec["attack_category"] = category
            rec["label"] = "attack"
            rec["source_file"] = log_path.name
            records.append(rec)

            if len(records) % 100_000 == 0:
                print(f"    {len(records):,} events parsed...")

    write_jsonl(PARSED / "splunk_attack_events.jsonl", records)


def _parse_windows_xml_event(xml_str):
    """Parse a single Windows Event XML string into a flat dict."""
    rec = {
        "timestamp": "",
        "event_type": "other",
        "event_id": "",
        "source_host": "",
        "user": "",
        "process_name": "",
        "parent_process": "",
        "command_line": "",
        "source_ip": "",
        "dest_ip": "",
        "dest_port": "",
    }

    try:
        # Remove namespace for easier parsing
        xml_str = re.sub(r'\s+xmlns=["\'][^"\']*["\']', "", xml_str)
        root = ET.fromstring(xml_str)

        # System fields
        system = root.find("System")
        if system is not None:
            eid_el = system.find("EventID")
            if eid_el is not None:
                rec["event_id"] = eid_el.text or ""
                rec["event_type"] = _map_windows_event_type({"EventID": eid_el.text})

            tc = system.find("TimeCreated")
            if tc is not None:
                rec["timestamp"] = tc.get("SystemTime", "")

            comp = system.find("Computer")
            if comp is not None:
                rec["source_host"] = comp.text or ""

            channel = system.find("Channel")
            if channel is not None:
                rec["channel"] = channel.text or ""

        # EventData fields
        event_data = root.find("EventData")
        if event_data is not None:
            data_fields = {}
            for data_el in event_data.findall("Data"):
                name = data_el.get("Name", "")
                value = data_el.text or ""
                if name:
                    data_fields[name] = value

            rec["user"] = data_fields.get("SubjectUserName", data_fields.get("TargetUserName", ""))
            rec["process_name"] = data_fields.get("NewProcessName", data_fields.get("Image", ""))
            rec["parent_process"] = data_fields.get("ParentProcessName", data_fields.get("ParentImage", ""))
            rec["command_line"] = data_fields.get("CommandLine", "")[:500]
            rec["source_ip"] = data_fields.get("IpAddress", data_fields.get("SourceAddress", ""))
            rec["dest_ip"] = data_fields.get("DestinationIp", data_fields.get("DestinationAddress", ""))
            rec["dest_port"] = data_fields.get("DestinationPort", "")
            rec["logon_type"] = data_fields.get("LogonType", "")
            rec["target_user"] = data_fields.get("TargetUserName", "")
            rec["subject_domain"] = data_fields.get("SubjectDomainName", "")

    except ET.ParseError:
        rec["raw"] = xml_str[:300]

    # Filter empty
    return {k: v for k, v in rec.items() if v}


def _mitre_to_category(mitre_id):
    mapping = {
        "T1003": "credential_theft", "T1110": "brute_force",
        "T1078": "credential_theft", "T1098": "credential_theft",
        "T1021": "lateral_movement", "T1570": "lateral_movement",
        "T1059": "execution", "T1204": "execution",
        "T1053": "execution", "T1047": "execution",
        "T1071": "c2", "T1572": "c2",
        "T1486": "ransomware", "T1566": "phishing",
        "T1055": "priv_esc", "T1134": "priv_esc", "T1548": "priv_esc",
        "T1041": "exfiltration", "T1567": "exfiltration",
        "T1046": "recon", "T1033": "recon", "T1049": "recon",
        "T1016": "recon", "T1018": "recon",
        "T1190": "web_attack", "T1133": "web_attack",
        "T1499": "dos", "T1014": "defense_evasion",
    }
    base = mitre_id.split(".")[0] if mitre_id else ""
    return mapping.get(base, "unknown")


# ---------------------------------------------------------------------------
# 8. Sentinel CSV logs
# ---------------------------------------------------------------------------
def parse_sentinel_csvs():
    sentinel_dir = RAW_LOGS / "sentinel"
    if not sentinel_dir.exists():
        print("SKIP: Sentinel raw_logs not found")
        return
    print("Parsing Sentinel ingested logs (CSV)...")
    records = []

    for csv_path in sorted(sentinel_dir.glob("*ingestedlogs.csv")):
        try:
            with open(csv_path, "r", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rec = {
                        "timestamp": row.get("TimeGenerated [UTC]", row.get("TimeGenerated", "")),
                        "event_type": "other",
                        "log_source": f"sentinel_{_sentinel_source(csv_path.name)}",
                        "source_host": row.get("Computer", ""),
                        "raw": row.get("RawData", row.get("Message", ""))[:500],
                        "label": "normal",
                        "source_file": csv_path.name,
                    }
                    # Try to classify from raw content
                    raw = rec.get("raw", "").lower()
                    if "auth" in raw or "login" in raw or "logon" in raw:
                        rec["event_type"] = "auth_success"
                    elif "dns" in raw or "query" in raw:
                        rec["event_type"] = "dns_query"
                    elif "connect" in raw or "traffic" in raw:
                        rec["event_type"] = "net_connect"

                    records.append(rec)
        except Exception:
            continue

    write_jsonl(PARSED / "sentinel_logs.jsonl", records)


def _sentinel_source(filename):
    # sentinel_asim_cisco_meraki_authentication_ingestedlogs.csv -> cisco_meraki
    parts = filename.replace("sentinel_asim_", "").replace("_ingestedlogs.csv", "")
    return parts[:40]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("PARSING ALL DATASETS TO JSONL")
    print("=" * 60)

    parse_zeek_conn()
    parse_zeek_dns()
    parse_zeek_http()
    parse_auth_log()
    parse_otrf()
    parse_elastic_samples()
    parse_splunk_attack_logs()
    parse_sentinel_csvs()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    total = 0
    for name, count in sorted(stats.items()):
        label = "NORMAL" if "normal" not in name and "attack" not in name else ""
        print(f"  {name:40s} {count:>10,} records")
        total += count
    print(f"  {'TOTAL':40s} {total:>10,} records")
    print("\nAll parsed files in:", PARSED)
