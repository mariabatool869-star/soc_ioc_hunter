# SOC IOC Hunter — Standard Operating Procedure (SOP)

Internal runbook for analysts and engineers. For product overview and install, see [README.md](README.md).

## Handover statement

This SOP is your team's **complete independence package**.

I built this tool, tested it, and documented every moving part below. Once you run the health check and see the `reports/` folder populate, you do not need ongoing contact for day-to-day maintenance.

**What you own after delivery:**

- Full source code (GitHub access)
- This SOP (troubleshooting + runbooks)
- Config templates (ready for your API keys)

**What is not included:** Ongoing 24/7 support, free feature additions, or debugging your network/firewall. Custom work (Splunk integration, Slack alerts, multi-source enrichment) is a **new fixed-price project** — not a quick favor.

**IOC** = Indicator of Compromise (here: an IP address that may warrant investigation).

---

## One-line production run

```bash
python ioc_check.py --input ips.txt --config config.yaml --output-dir ./reports
```

---

## 1. Quick start (L1 analysts)

> Goal: enrich a list of IPs and open today’s report.

1. Confirm `config.yaml` exists (copy from `config.example.yaml` if needed) and `api_key` is set.  
2. Put investigation IPs in `ips.txt` (one per line; `#` starts a comment).  
3. Health check:

```bash
python check_api.py
```

Expected: HTTP **200** and a printed abuse score for `8.8.8.8`.

4. Run enrichment:

```bash
python ioc_check.py
```

5. Open the newest folder under `reports/` — use `report.csv` for triage and `malicious_ips.txt` for escalation / block candidates.  
6. If needed, attach `logs/run_*.log` to the ticket as the run audit trail.

---

## 2. Health check

```bash
python check_api.py
```

| Result | Meaning | Action |
|--------|---------|--------|
| Status 200 | Key and network OK | Proceed with `ioc_check.py` |
| Status 401 | Invalid key | Regenerate at AbuseIPDB → update `config.yaml` |
| Timeout / connection error | Network, proxy, or firewall | Check egress to `api.abuseipdb.com` |

---

## 3. Troubleshooting triage

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `[FATAL] config.yaml not found` | Local config missing | `copy config.example.yaml config.yaml` and set `api_key` |
| `Unauthorized (401)` / fatal auth | Invalid or expired API key | New key from AbuseIPDB; update `config.yaml` |
| `API Error: Status code 429` | Rate limit | Raise `request_delay` (e.g. `1.0`); reduce list size; check plan quota |
| Repeated 5xx errors | AbuseIPDB / network instability | Tool retries transient 5xx; wait and re-run remaining IPs |
| `SKIPPED_PRIVATE` in CSV | RFC1918 / private address | Expected when `skip_private_ips: true` — do not treat as reputation score |
| Input file not found | Wrong `--input` path | Pass correct path or set `input_file` in config |
| Empty / unexpected scores | Quota or incomplete run | Check summary FAILED count and log file |

---

## 4. Configuration reference (engineering)

Copy `config.example.yaml` → `config.yaml` (gitignored).

| Key | Purpose |
|-----|---------|
| `api_key` | AbuseIPDB API key (required) |
| `base_url` | Check endpoint URL |
| `retry_attempts` / `retry_delay` | Retries on 429 and 5xx |
| `request_delay` | Pause between successful requests (rate limiting) |
| `skip_private_ips` | Skip RFC1918 / private addresses |
| `input_file` / `output_dir` / `log_dir` | Paths |
| `thresholds.malicious` / `thresholds.suspicious` | Verdict bands |

`ConfigLoader.require()` fails fast if required keys are missing or empty.

### Verdict defaults

| Score | Verdict |
|------:|---------|
| 0–10 | SAFE |
| 11–50 | SUSPICIOUS |
| 51–100 | MALICIOUS |

---

## 5. Audit trail (investigation records)

Every successful run writes:

| Artifact | Path | Use |
|----------|------|-----|
| CSV report | `reports/<timestamp>/report.csv` | Ticket evidence / analyst review |
| Blocklist | `reports/<timestamp>/malicious_ips.txt` | Candidates for further action |
| Run log | `logs/run_<timestamp>.log` | Console-equivalent audit of the run |

These files help you show **what was checked, when, and with what verdict**. They support internal investigation hygiene and ticket evidence. They are **not** a SOC 2 / ISO certification by themselves.

---

## 6. Module map

| File | Responsibility |
|------|----------------|
| `ioc_check.py` | Orchestration / CLI |
| `abuseipdb_client.py` | AbuseIPDB HTTP + retries |
| `classifier.py` | Scoring + private IP detection |
| `reporting.py` | Timestamped report writers |
| `logger.py` | Console + file logging |
| `config_loader.py` | YAML configuration |
| `check_api.py` | Standalone connectivity smoke test |
| `tests/` | Unit tests (`pytest`) |

Outputs belong under `reports/` and `logs/`. Do not rely on root-level leftover `report.csv` / `malicious_ips.txt` if present.

---

## 7. Demo script (standups / interviews)

1. Show `ips.txt` (mix of public + private samples).  
2. `python check_api.py`  
3. `python ioc_check.py` — note private IPs skipped.  
4. Open newest `reports/<run>/` and a matching `logs/run_*.log`.  
5. State limits: reputation ≠ compromise; CDNs and Tor exits need judgment.

### Pitch (15 seconds)

> SOC IOC Hunter takes investigation IPs, enriches them with AbuseIPDB, and produces a timestamped CSV plus a high-confidence malicious list for triage.

### Interview card (1–2 minutes)

| Point | One-liner |
|-------|-----------|
| Problem | Too many IPs to enrich manually |
| Approach | AbuseIPDB scores → SAFE / SUSPICIOUS / MALICIOUS |
| Design | Config-driven, modular, retries, rate delay, private-IP skip, timestamped reports + logs |
| Outputs | `report.csv` + `malicious_ips.txt` + `logs/run_*.log` |
| Limit | One signal among many — analyst still decides |

---

## 8. Extending later (optional)

To add another intel source (e.g. VirusTotal):

1. Add its API key under `config.yaml`  
2. Add a new client module patterned on `abuseipdb_client.py`  
3. Wire results into `ioc_check.py` / reporting (CLI must orchestrate the second source)

Keep thresholds and secrets out of source code.

---

## 9. Security notes

- Never commit real `api_key` values  
- Rotate keys shared outside secure channels  
- Treat client IPs and investigation lists as sensitive  
- Prefer anonymized samples in public screenshots  

---

## 10. Owner checklist

- [ ] `python check_api.py` returns 200  
- [ ] Sample run creates `reports/<timestamp>/` and `logs/run_*.log`  
- [ ] `config.yaml` is gitignored and not shared in Slack/email  
- [ ] `python -m pytest -q` passes  
- [ ] I have saved this SOP offline (you own this document after handover)

---

## 11. Scope of delivery (support boundary)

This project was delivered as a **fixed-price, one-time engagement**.

**In scope (delivered):**

- Functional CLI tool (AbuseIPDB enrichment + CSV reporting + audit logging)
- This SOP (`TEAM_GUIDE.md`) and product docs (`README.md`)
- `config.example.yaml` and `requirements.txt`

**Out of scope (new project required):**

- Adding new data sources (VirusTotal, MISP, Hybrid Analysis)
- Writing custom parsers for your SIEM (Splunk / ELK exports)
- Building a GUI or web dashboard
- Running this tool on your production servers (your IT team handles deployment)
- 24/7 emergency fixes (if AbuseIPDB changes their API in a breaking way, that is a new engagement)

**How to request new work:** Email [mariabatool869@gmail.com](mailto:mariabatool869@gmail.com) with the subject `New Project: [Your Feature]`. You will get a fixed price and delivery window within 24 hours.
