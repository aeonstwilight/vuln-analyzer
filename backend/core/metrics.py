import pandas as pd


def generate_metrics(df: pd.DataFrame) -> dict:
    return {
        "total":    len(df),
        "critical": int((df["severity"] == "Critical").sum()),
        "high":     int((df["severity"] == "High").sum()),
        "medium":   int((df["severity"] == "Medium").sum()),
        "low":      int((df["severity"] == "Low").sum()),
        "expired":  int(df["expired"].sum()),
        "oldest":   df["first_discovered"].min().isoformat() if not df["first_discovered"].isna().all() else None,
        "hosts":    int(df["host"].nunique()),
    }


def calculate_risk(metrics: dict) -> tuple[int, str]:
    score = metrics["critical"] * 5 + metrics["high"] * 3 + metrics["medium"]
    if score <= 20:
        rating = "Low"
    elif score <= 50:
        rating = "Moderate"
    elif score <= 100:
        rating = "High"
    else:
        rating = "Severe"
    return score, rating


def compare_scans(df_new: pd.DataFrame, df_old: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    key = ["host", "plugin_id"]
    new_idx = df_new.set_index(key).index
    old_idx = df_old.set_index(key).index
    new_only  = df_new[~df_new.set_index(key).index.isin(old_idx)]
    resolved  = df_old[~df_old.set_index(key).index.isin(new_idx)]
    unchanged = df_new[ df_new.set_index(key).index.isin(old_idx)]
    return new_only, resolved, unchanged
