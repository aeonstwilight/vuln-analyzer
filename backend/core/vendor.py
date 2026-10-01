import pandas as pd


VENDOR_COLUMN_MAPS = {
    "Nessus": {
        "Plugin ID":        "plugin_id",
        "Plugin Name":      "plugin_name",
        "Host":             "host",
        "CVSS":             "cvss",
        "CVE":              "cve_refs",       # comma-separated CVE list
        "Exploit Available":"exploit_available",
        "First Discovered": "first_discovered",
        "Last Observed":    "last_observed",
        "Solution":         "solution",
    },
    "Qualys": {
        "QID":        "plugin_id",
        "Title":      "plugin_name",
        "IP":         "host",
        "CVSS Base":  "cvss",
        "CVE ID":     "cve_refs",
        "First Found":"first_discovered",
        "Last Found": "last_observed",
        "Solution":   "solution",
    },
    "Rapid7": {
        "Vulnerability ID":  "plugin_id",
        "Title":             "plugin_name",
        "Asset IP Address":  "host",
        "CVSS Score":        "cvss",
        "CVEs":              "cve_refs",
        "Exploits":          "exploit_available",
        "Date Discovered":   "first_discovered",
        "Date Observed":     "last_observed",
        "Solution":          "solution",
    },
    # OpenVAS / GVM CSV export (Reports > CSV Results)
    "OpenVAS": {
        "NVT OID":   "plugin_id",
        "NVT Name":  "plugin_name",
        "IP":        "host",
        "CVSS":      "cvss",
        "CVEs":      "cve_refs",
        "Timestamp": "first_discovered",
        # Timestamp also maps to last_observed — handled in normalize_data
        "Solution":  "solution",
    },
    # Wiz cloud security platform CSV export
    # Severity column is text (CRITICAL/HIGH/MEDIUM/LOW) — converted to CVSS in normalize_data
    "Wiz": {
        "Wiz Vulnerability ID": "plugin_id",
        "Name":                 "plugin_name",
        "Resource Name":        "host",
        "Severity":             "_severity_text",
        "CVE IDs":              "cve_refs",
        "First Detected":       "first_discovered",
        "Last Detected":        "last_observed",
        "Remediation":          "solution",
    },
    # Microsoft Defender Vulnerability Management CSV export
    # plugin_id is the CVE ID itself — cve_refs mirrors it
    "Defender": {
        "CVE ID":                  "plugin_id",
        "Vulnerability name":      "plugin_name",
        "Device name":             "host",
        "CVSS score":              "cvss",
        "First seen":              "first_discovered",
        "Last seen":               "last_observed",
        "Remediation description": "solution",
    },
}

OPTIONAL_COLS = {"exploit_available", "solution", "cve_refs"}

# Text-severity vendors that lack a numeric CVSS column
_SEVERITY_TO_CVSS = {
    "critical":      9.5,
    "high":          7.5,
    "medium":        5.0,
    "low":           2.0,
    "informational": 0.0,
    "info":          0.0,
    "none":          0.0,
}


def detect_vendor(df: pd.DataFrame) -> str:
    cols = {c.lower().strip() for c in df.columns}
    # Most-specific checks first to avoid false positives
    if "nvt oid" in cols or "nvt name" in cols:
        return "OpenVAS"
    if "wiz vulnerability id" in cols or ("resource name" in cols and "first detected" in cols):
        return "Wiz"
    if "cve id" in cols and "device name" in cols:
        return "Defender"
    if "plugin id" in cols:
        return "Nessus"
    if "qid" in cols:
        return "Qualys"
    if "vulnerability id" in cols or "vuln id" in cols:
        return "Rapid7"
    return "Unknown"


def normalize_data(df: pd.DataFrame, vendor: str) -> tuple[pd.DataFrame, list[str]]:
    """Returns (normalized_df, missing_columns). normalized_df uses snake_case internal names."""
    if vendor not in VENDOR_COLUMN_MAPS:
        raise ValueError(f"Unsupported vendor: {vendor}")

    df = df.copy()
    df.columns = df.columns.str.strip()
    col_map = VENDOR_COLUMN_MAPS[vendor]
    missing = []
    normalized = pd.DataFrame()

    for src, dst in col_map.items():
        if src in df.columns:
            normalized[dst] = df[src]
        else:
            normalized[dst] = ""
            if dst not in OPTIONAL_COLS and not dst.startswith("_"):
                missing.append(src)

    # OpenVAS: duplicate Timestamp into last_observed as well
    if vendor == "OpenVAS" and "first_discovered" in normalized.columns:
        normalized["last_observed"] = normalized["first_discovered"]

    # Text-severity vendors: convert Severity string → CVSS float
    if "_severity_text" in normalized.columns:
        normalized["cvss"] = (
            normalized["_severity_text"]
            .str.lower()
            .str.strip()
            .map(_SEVERITY_TO_CVSS)
            .fillna(0.0)
        )
        normalized = normalized.drop(columns=["_severity_text"])

    return normalized, missing
