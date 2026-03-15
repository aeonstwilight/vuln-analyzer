import io
import pandas as pd
from fastapi import APIRouter, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse

from core import (
    detect_vendor, normalize_data, clean_and_enrich,
    compare_scans, COMPLIANCE_PROFILES
)

router = APIRouter(prefix="/compare", tags=["compare"])


def _df_to_records(df: pd.DataFrame) -> list[dict]:
    out = df.copy()
    for col in ["first_discovered", "last_observed"]:
        if col in out.columns:
            out[col] = out[col].astype(str).replace("NaT", None)
    out["expired"] = out["expired"].astype(bool)
    out = out.where(pd.notna(out), None)
    return out.to_dict(orient="records")


def _load_and_enrich(contents: bytes, vendor_override: str, profile: dict):
    df_raw = pd.read_csv(io.BytesIO(contents))
    vendor = detect_vendor(df_raw) if vendor_override == "Auto Detect" else vendor_override
    if vendor == "Unknown":
        raise HTTPException(400, "Could not detect vendor format.")
    df_norm, _ = normalize_data(df_raw, vendor)
    return clean_and_enrich(df_norm, profile), vendor


@router.post("")
async def compare(
    old_file: UploadFile = File(...),
    new_file: UploadFile = File(...),
    vendor_override: str = Form("Auto Detect"),
    profile_name: str    = Form("FedRAMP Moderate/High"),
):
    profile = COMPLIANCE_PROFILES.get(profile_name, COMPLIANCE_PROFILES["FedRAMP Moderate/High"])

    old_contents = await old_file.read()
    new_contents = await new_file.read()

    try:
        df_old, vendor_old = _load_and_enrich(old_contents, vendor_override, profile)
        df_new, vendor_new = _load_and_enrich(new_contents, vendor_override, profile)
    except Exception as e:
        raise HTTPException(400, f"Error processing files: {e}")

    new_only, resolved, unchanged = compare_scans(df_new, df_old)

    return JSONResponse({
        "summary": {
            "new":       len(new_only),
            "resolved":  len(resolved),
            "unchanged": len(unchanged),
        },
        "new":       _df_to_records(new_only),
        "resolved":  _df_to_records(resolved),
        "unchanged": _df_to_records(unchanged),
    })
