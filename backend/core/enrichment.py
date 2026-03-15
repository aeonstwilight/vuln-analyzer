from datetime import datetime
import pandas as pd


COMPLIANCE_PROFILES = {
    "FedRAMP Moderate/High": {"Critical": 30, "High": 30, "Medium": 90,  "Low": 180},
    "PCI DSS":               {"Critical": 5,  "High": 15, "Medium": 30,  "Low": 90},
    "NIST 800-53":           {"Critical": 7,  "High": 30, "Medium": 60,  "Low": 180},
}


def severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    elif cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    elif cvss > 0.0:
        return "Low"
    return "Low"


def clean_and_enrich(df: pd.DataFrame, profile: dict) -> pd.DataFrame:
    df = df.copy()
    df["cvss"] = pd.to_numeric(df["cvss"], errors="coerce").fillna(0)
    df["severity"] = df["cvss"].apply(severity_from_cvss)
    df["first_discovered"] = pd.to_datetime(df["first_discovered"], errors="coerce").dt.tz_localize(None)
    df["last_observed"]    = pd.to_datetime(df["last_observed"],    errors="coerce").dt.tz_localize(None)
    df = df.drop_duplicates(subset=["host", "plugin_id"])

    today = pd.Timestamp(datetime.today())
    df["age_days"]          = (today - df["first_discovered"]).dt.days
    df["remediation_days"]  = df["severity"].map(lambda s: profile.get(s, 90))
    df["days_left"]         = df["remediation_days"] - df["age_days"]
    df["expired"]           = df["days_left"] < 0

    return df
