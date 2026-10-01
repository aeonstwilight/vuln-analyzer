# VulnAnalyzer

A web tool that turns a raw vulnerability scan export into a ranked answer to "what do we fix first, and what is overdue?" Built with FastAPI and React.

Upload a CSV from Nessus, Qualys, Rapid7, OpenVAS, Wiz or Microsoft Defender. VulnAnalyzer normalizes it, enriches it with exploit intelligence, scores every finding, and tracks deadlines against the compliance profile you choose, including the FedRAMP Consolidated Rules for 2026.

I built it to speed up POA&M management for FedRAMP continuous monitoring, where the monthly work is the same every time: merge scanner output, work out what is late, and decide what matters.

---

## Features

- **Six scanner formats.** Auto-detects Nessus, Qualys, Rapid7, OpenVAS, Wiz and Defender exports and maps them to one schema.
- **Exploit intelligence.** Flags findings in the CISA Known Exploited Vulnerabilities catalog, adds EPSS exploitation probability, and pulls descriptions and CWE from NVD.
- **Risk-based prioritization.** Scores each finding 0-100 on threat, severity, fleet exposure and deadline pressure, with the reason shown for every rank.
- **Fix-first plan.** Groups findings into remediation actions: one patch across 40 hosts is one line, not 40.
- **Deadline tracking.** Days remaining and overdue findings per compliance profile: FedRAMP Moderate/High, PCI DSS, NIST 800-53, custom windows, or FedRAMP 2026.
- **FedRAMP 2026 evaluation.** Proposes the three evaluations the 2026 rules require and applies the class-based timeframes. See below.
- **Scan comparison.** Diffs two scans into new, resolved and unchanged findings.
- **Exports.** PDF summary report, full JSON, OSCAL POA&M, and a FedRAMP 2026 vulnerability detail file.

---

## FedRAMP 2026 profiles

Before 2026, FedRAMP deadlines came from scanner severity: High in 30 days, Moderate in 90, Low in 180. The [Consolidated Rules for 2026](https://www.fedramp.gov/2026/) replace that. Providers must now evaluate each vulnerability for three things, and the deadline depends on all three plus the Certification Class:

| Evaluation | Rule | How VulnAnalyzer proposes it |
|------------|------|------------------------------|
| Likely exploitable | VER-EVA-ELX | Yes if listed in CISA KEV, if EPSS is at or above 10%, or if the scanner reports an exploit. If exploit intelligence could not be fetched, the finding is assumed likely exploitable. |
| Internet-reachable | VER-EVA-EIR | From the asset context file. Hosts not in the file use the assumption you select, and are marked as assumed. |
| Potential agency impact, N1 to N5 | VER-EVA-EPA | The lower of the asset's impact rating and a cap from scanner severity (Critical N5, High N4, Medium N3, Low N2). |

From those it applies:

- **Timeframes** for Class B, C and D from VDR-TFR-PVR. N1 findings have no fixed timeframe.
- **Accepted vulnerabilities.** Findings open more than 192 days are flagged, because VER-TFR-MAV requires them to be reported as accepted.
- **Reportable incident rules.** Findings that meet VER-TFR-IRI or VER-TFR-NRI are flagged with the strength the rule uses for that class ("should" or "may").

### These are proposals, not evaluations

The rules require the provider to evaluate each vulnerability in the context of the cloud service. A tool reading a CSV cannot do that. VulnAnalyzer produces a first pass for an analyst to confirm, and every proposed value carries the evidence it was based on. Two limits to know about:

- Deadlines are counted from first discovery. The rules count from completed evaluation, which a scan export does not record. Discovery is earlier, so the result is the stricter of the two.
- The `/report/ver` export lists the fields VER-RPT-VDT requires. It has not been validated against FedRAMP's published JSON schema, and it leaves evaluation time, rating history and final disposition empty for the analyst.

Rules are as published on fedramp.gov on 2026-10-01. They are still being revised.

### Asset context file

A scan cannot tell you which hosts receive traffic from the internet or how much damage their compromise would do to agency customers. Supply that in a CSV:

```csv
host,internet_reachable,impact
203.0.113.0/24,yes,N4
10.20.1.15,yes,N5
10.20.2.0/24,no,N4
10.20.3.*,no,N2
```

`host` can be an exact name or IP, a CIDR range, or a `*` wildcard. The most specific match wins. `impact` is the worst effect on agency customers if that asset were compromised. See `example_data/example_asset_context.csv`.

---

## Getting started

Requires Python 3.11+ and Node.js 18+.

```bash
git clone https://github.com/aeonstwilight/vuln-analyzer.git
cd vuln-analyzer
python start.py
```

`start.py` builds the frontend on first run, installs backend dependencies if needed, and serves everything at `http://localhost:8000`. Use `--port` to change the port and `--rebuild` to force a frontend rebuild.

To try it, drop `example_data/example_nessus_cves.csv` into the page. For the FedRAMP 2026 view, pick a "FedRAMP 2026" profile in the sidebar and add `example_data/example_asset_context.csv`.

### Development mode

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server at `http://localhost:5173` proxies API calls to the backend.

### Tests

```bash
cd backend
python -m unittest discover tests
```

---

## What leaves your machine

Scan data stays local. Enrichment makes three outbound requests:

| Service | What is sent |
|---------|--------------|
| CISA KEV | Nothing. The full catalog is downloaded and cached for 24 hours. |
| FIRST EPSS | The CVE IDs found in the scan. |
| NVD | Up to 30 CVE IDs per analysis (`NVD_MAX_CVEs`). Set `NVD_API_KEY` for a higher rate limit. |

No host names, IPs or findings are sent. To run with no outbound requests at all, pass `skip_enrichment=true` to `/analyze`.

---

## API

| Method | Endpoint        | Description |
|--------|-----------------|-------------|
| GET    | `/health`       | Health check |
| GET    | `/profiles`     | List compliance profiles |
| POST   | `/analyze`      | Upload a CSV, returns the enriched analysis as JSON |
| POST   | `/compare`      | Upload two CSVs, returns the diff |
| POST   | `/report/pdf`   | PDF summary report |
| POST   | `/report/json`  | Full analysis as a JSON file |
| POST   | `/report/oscal` | OSCAL 1.1.2 POA&M |
| POST   | `/report/ver`   | FedRAMP 2026 vulnerability detail (2026 profiles only) |

Interactive documentation is at `http://localhost:8000/docs`.

### Form fields

| Field | Default | Notes |
|-------|---------|-------|
| `file` | required | CSV scan export |
| `vendor_override` | `Auto Detect` | `Nessus`, `Qualys`, `Rapid7`, `OpenVAS`, `Wiz`, `Defender` |
| `profile_name` | `FedRAMP Moderate/High` | See `/profiles` |
| `critical_days`, `high_days`, `medium_days`, `low_days` | 30, 30, 90, 180 | `Custom` profile only |
| `skip_enrichment` | `false` | `/analyze` only |
| `asset_context` | none | FedRAMP 2026 profiles: asset context CSV |
| `assume_internet_reachable` | `false` | FedRAMP 2026 profiles: assumption for hosts not in the file |
| `default_impact` | `3` | FedRAMP 2026 profiles: impact rating for hosts not in the file |
| `epss_threshold` | `0.10` | FedRAMP 2026 profiles: EPSS level treated as likely exploitable |

```bash
curl -X POST http://localhost:8000/analyze \
  -F "file=@example_data/example_nessus_cves.csv" \
  -F "profile_name=FedRAMP 2026 Class C" \
  -F "asset_context=@example_data/example_asset_context.csv"
```

Scan comparison uses the severity-based windows for every profile.

---

## Supported CSV formats

| Scanner  | Columns used for detection and mapping |
|----------|----------------------------------------|
| Nessus   | `Plugin ID`, `Plugin Name`, `Host`, `CVSS`, `CVE`, `First Discovered`, `Last Observed` |
| Qualys   | `QID`, `Title`, `IP`, `CVSS Base`, `CVE ID`, `First Found`, `Last Found` |
| Rapid7   | `Vulnerability ID`, `Title`, `Asset IP Address`, `CVSS Score`, `CVEs`, `Date Discovered` |
| OpenVAS  | `NVT OID`, `NVT Name`, `IP`, `CVSS`, `CVEs`, `Timestamp` |
| Wiz      | `Wiz Vulnerability ID`, `Name`, `Resource Name`, `Severity`, `CVE IDs`, `First Detected` |
| Defender | `CVE ID`, `Vulnerability name`, `Device name`, `CVSS score`, `First seen`, `Last seen` |

Missing optional columns (`Solution`, `Exploit Available`, CVE references) produce a warning and do not fail the analysis.

---

## Project structure

```
vuln-analyzer/
├── start.py                    # Single-command launcher
├── backend/
│   ├── main.py                 # FastAPI app
│   ├── report_generator.py     # PDF report (ReportLab + Matplotlib)
│   ├── core/
│   │   ├── vendor.py           # Scanner detection and normalization
│   │   ├── enrichment.py       # Severity mapping, age, severity-based deadlines
│   │   ├── cve_enrichment.py   # CISA KEV, EPSS and NVD lookups
│   │   ├── prioritization.py   # Priority score, fix-first plan, fleet risk
│   │   ├── fedramp2026.py      # FedRAMP 2026 evaluation and timeframes
│   │   ├── metrics.py          # Counts and scan diff
│   │   └── serialization.py    # DataFrame to JSON
│   ├── routers/                # /analyze, /compare, /report/*
│   └── tests/
├── frontend/src/               # React UI (Dashboard, Compare)
└── example_data/
```

| Layer    | Technology |
|----------|------------|
| Backend  | Python, FastAPI, pandas, httpx, ReportLab, Matplotlib |
| Frontend | React 18, Vite, Recharts |

---

## Roadmap

- [ ] Validate the FedRAMP 2026 export against the published JSON schema
- [ ] Record evaluation time and rating history so timeframes count from evaluation
- [ ] Group findings into logical sets for evaluation (VER-EVA-GRV)
- [ ] Risk trend across multiple scans
- [ ] Asset grouping by subnet, environment or owner

---

## Security note

Do not commit real scan CSVs to this repository. The `.gitignore` excludes `*.csv` by default; only files under `example_data/` are tracked.

## License

MIT
