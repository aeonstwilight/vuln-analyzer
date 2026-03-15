import pandas as pd


VENDOR_COLUMN_MAPS = {
    "Nessus": {
        "Plugin ID":        "plugin_id",
        "Plugin Name":      "plugin_name",
        "Host":             "host",
        "CVSS":             "cvss",
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
        "First Found":"first_discovered",
        "Last Found": "last_observed",
        "Solution":   "solution",
    },
    "Rapid7": {
        "Vulnerability ID":  "plugin_id",
        "Title":             "plugin_name",
        "Asset IP Address":  "host",
        "CVSS Score":        "cvss",
        "Exploits":          "exploit_available",
        "Date Discovered":   "first_discovered",
        "Date Observed":     "last_observed",
        "Solution":          "solution",
    },
}

OPTIONAL_COLS = {"exploit_available", "solution"}


def detect_vendor(df: pd.DataFrame) -> str:
    cols = [c.lower().strip() for c in df.columns]
    if "plugin id" in cols:
        return "Nessus"
    elif "qid" in cols:
        return "Qualys"
    elif "vulnerability id" in cols or "vuln id" in cols:
        return "Rapid7"
    return "Unknown"


def normalize_data(df: pd.DataFrame, vendor: str) -> tuple[pd.DataFrame, list[str]]:
    """
    Returns (normalized_df, missing_columns).
    normalized_df uses snake_case internal column names.
    """
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
            if dst not in OPTIONAL_COLS:
                missing.append(src)

    return normalized, missing
