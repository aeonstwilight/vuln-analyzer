import io
import pandas as pd
from fastapi import APIRouter, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse

from core import (
    detect_vendor, normalize_data, clean_and_enrich,
    generate_metrics, calculate_risk, COMPLIANCE_PROFILES
)

router = APIRouter(prefix="/analyze", tags=["analyze"])


def _df_to_records(df: pd.DataFrame) -> list[dict]:
    """Serialize DataFrame to JSON-safe records."""
    out = df.copy()
    for col in ["first_discovered", "last_observed"]:
        if col in out.columns:
            out[col] = out[col].astype(str).replace("NaT", None)
    out["expired"] = out["expired"].astype(bool)
    out = out.where(pd.notna(out), None)
    return out.to_dict(orient="records")


@router.post("")
async def analyze(
    file: UploadFile = File(...),
    vendor_override: str = Form("Auto Detect"),
    profile_name: str = Form("FedRAMP Moderate/High"),
    critical_days: int  = Form(None),
    high_days: int      = Form(None),
    medium_days: int    = Form(None),
    low_days: int       = Form(None),
):
    if not file.filename.endswith(".csv"):
        raise HTTPException(400, "Only CSV files are supported.")

    contents = await file.read()
    try:
        df_raw = pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(400, f"Could not parse CSV: {e}")

    # Vendor detection
    vendor = detect_vendor(df_raw) if vendor_override == "Auto Detect" else vendor_override
    if vendor == "Unknown":
        raise HTTPException(400, "Could not detect vendor format. Try setting vendor_override.")

    # Profile resolution
    if profile_name == "Custom":
        profile = {
            "Critical": critical_days or 30,
            "High":     high_days     or 30,
            "Medium":   medium_days   or 90,
            "Low":      low_days      or 180,
        }
    else:
        profile = COMPLIANCE_PROFILES.get(profile_name, COMPLIANCE_PROFILES["FedRAMP Moderate/High"])

    df_norm, missing_cols = normalize_data(df_raw, vendor)
    df = clean_and_enrich(df_norm, profile)
    metrics = generate_metrics(df)
    score, rating = calculate_risk(metrics)

    return JSONResponse({
        "vendor":       vendor,
        "profile_name": profile_name,
        "profile":      profile,
        "metrics":      metrics,
        "risk": {
            "score":  score,
            "rating": rating,
        },
        "missing_columns": missing_cols,
        "vulnerabilities": _df_to_records(df),
    })
