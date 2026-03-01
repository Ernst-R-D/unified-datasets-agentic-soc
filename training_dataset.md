  datasets/
    normal/                          # Phase 1 -- MLM pretraining
      zeek_conn.jsonl     1,000,000 network connections
      zeek_http.jsonl     1,000,000 HTTP requests
      zeek_dns.jsonl        427,935 DNS queries
      ssh_auth.jsonl         86,839 SSH auth events
      sentinel_logs.jsonl     7,513 Sentinel ASIM logs
      elastic_samples.jsonl   5,656 Elastic integration samples

    attacks/                         # Phase 2 -- fine-tuning
      otrf_windows_events.jsonl  1,927,305 Windows event logs (MITRE mapped)
      splunk_attack_events.jsonl   115,783 attack reproductions (MITRE mapped)

Resume this session with:
claude --resume 0f0efb02-aba3-42fb-8453-2fb818e63463
