# VulnAnalyzer

A full-stack vulnerability scan analysis tool built with **FastAPI** and **React**.

Upload CSV exports from Nessus, Qualys, or Rapid7 and get instant risk scoring, SLA tracking, aging analysis, scan-to-scan comparison, and a one-click PDF executive report — all in a clean web UI.

---

## Features

- **Multi-vendor support** — auto-detects and normalizes Nessus, Qualys, and Rapid7 CSV exports into a unified schema
- **CVSS-based severity mapping** — Critical / High / Medium / Low derived from CVSS score
- **SLA compliance tracking** — calculates days remaining against configurable remediation deadlines, flags expired findings
- **Risk scoring** — weighted composite score with Low / Moderate / High / Severe rating
- **Scan comparison** — diff two scans side-by-side to surface New, Resolved, and Unchanged findings
- **Interactive charts** — severity donut, top hosts by vuln count, aging buckets, SLA compliance by severity
- **PDF executive report** — one-click export with cover page, key findings, all charts, per-severity tables, and remediation priorities
- **Compliance profiles** — FedRAMP Moderate/High, PCI DSS, NIST 800-53, or fully custom SLA windows

---

## Tech stack

| Layer    | Technology |
|----------|------------|
| Backend  | Python · FastAPI · pandas · ReportLab · Matplotlib |
| Frontend | React 18 · Vite · Recharts |
| API      | REST · multipart/form-data file upload |

---

## Project structure

```
vuln-analyzer/
├── backend/
│   ├── main.py                 # FastAPI app entry point
│   ├── requirements.txt
│   ├── report_generator.py     # PDF report (ReportLab + Matplotlib)
│   ├── core/
│   │   ├── vendor.py           # Vendor detection + CSV normalization
│   │   ├── enrichment.py       # CVSS mapping, SLA calculation, aging
│   │   └── metrics.py          # Risk scoring, scan diff logic
│   └── routers/
│       ├── analyze.py          # POST /analyze
│       ├── compare.py          # POST /compare
│       └── report.py           # POST /report/pdf
└── frontend/
    ├── index.html
    ├── vite.config.js
    ├── package.json
    └── src/
        ├── App.jsx             # Sidebar nav, compliance + vendor settings
        ├── api/client.js       # All fetch calls, PDF blob download
        ├── components/
        │   └── index.jsx       # SeverityBadge, MetricCard, VulnTable, FileDropZone
        └── pages/
            ├── Dashboard.jsx   # Upload, analyze, charts, filterable table, PDF export
            └── Compare.jsx     # Two-file diff, tabbed New/Resolved/Unchanged view
```

---

## Getting started

### Prerequisites

- Python 3.11+
- Node.js 18+

### 1. Clone

```bash
git clone https://github.com/YOUR_USERNAME/vuln-analyzer.git
cd vuln-analyzer
```

### 2. Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

API running at `http://localhost:8000`
Interactive docs at `http://localhost:8000/docs`

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

App running at `http://localhost:5173`

The Vite dev server proxies `/analyze`, `/compare`, `/report`, and `/profiles` to the backend automatically — no CORS configuration needed during development.

---

## API reference

| Method | Endpoint      | Description                             |
|--------|---------------|-----------------------------------------|
| GET    | `/health`     | Health check                            |
| GET    | `/profiles`   | List available compliance profiles      |
| POST   | `/analyze`    | Upload a CSV, returns enriched JSON     |
| POST   | `/compare`    | Upload two CSVs, returns diff JSON      |
| POST   | `/report/pdf` | Upload a CSV, returns PDF binary stream |

### POST `/analyze` form fields

| Field             | Type    | Default                   | Notes                           |
|-------------------|---------|---------------------------|---------------------------------|
| `file`            | File    | required                  | CSV scan export                 |
| `vendor_override` | string  | `"Auto Detect"`           | `Nessus`, `Qualys`, or `Rapid7` |
| `profile_name`    | string  | `"FedRAMP Moderate/High"` | See `/profiles`                 |
| `critical_days`   | integer | 30                        | Custom profile only             |
| `high_days`       | integer | 30                        | Custom profile only             |
| `medium_days`     | integer | 90                        | Custom profile only             |
| `low_days`        | integer | 180                       | Custom profile only             |

---

## Try it with example data

```bash
curl -X POST http://localhost:8000/analyze \
  -F "file=@example_data/example_nessus.csv" \
  -F "profile_name=FedRAMP Moderate/High"
```

Or drag `example_data/example_nessus.csv` into the web UI.

---

## Supported CSV formats

| Vendor  | Key columns (auto-detected) |
|---------|-----------------------------|
| Nessus  | `Plugin ID`, `Plugin Name`, `Host`, `CVSS`, `First Discovered`, `Last Observed` |
| Qualys  | `QID`, `Title`, `IP`, `CVSS Base`, `First Found`, `Last Found` |
| Rapid7  | `Vulnerability ID`, `Title`, `Asset IP Address`, `CVSS Score`, `Date Discovered` |

Missing optional columns (`Solution`, `Exploit Available`) produce a warning but do not fail the analysis.

---

## Production deployment

### Backend

```bash
pip install gunicorn
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### Frontend

```bash
cd frontend
npm run build
# Serve dist/ with nginx or any static host
```

### nginx config

```nginx
server {
    listen 80;

    location / {
        root /path/to/frontend/dist;
        try_files $uri /index.html;
    }

    location ~ ^/(analyze|compare|report|profiles|health) {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        client_max_body_size 50M;
    }
}
```

---

## Roadmap

- [ ] CISA KEV integration — flag CVEs actively exploited in the wild
- [ ] Asset grouping — tag hosts by subnet, environment, or owner
- [ ] Remediation tracker — mark findings in-progress or closed
- [ ] Risk trend dashboard — plot score over time across multiple scans
- [ ] Additional vendor support — OpenVAS, Tenable.io
- [ ] XLSX and STIX/JSON export for SIEM ingest

---

## Security note

Do not commit real scan CSVs to this repository. The `.gitignore` excludes `*.csv` by default — only files under `example_data/` are tracked.

---

## License

MIT
