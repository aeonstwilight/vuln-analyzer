import io
import pandas as pd
from fastapi import APIRouter, Depends, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse

from core import (
    detect_vendor, normalize_data, clean_and_enrich,
    generate_metrics, COMPLIANCE_PROFILES,
    enrich_with_cve_intel,
    compute_priority, build_remediation_plan, calculate_fleet_risk, priority_summary,
    df_to_records, apply_profile,
)
from .options import ver_options

router = APIRouter(prefix="/analyze", tags=["analyze"])


@router.post("")
async def analyze(
    file: UploadFile = File(...),
    vendor_override: str = Form("Auto Detect"),
    profile_name: str    = Form("FedRAMP Moderate/High"),
    critical_days: int   = Form(None),
    high_days: int       = Form(None),
    medium_days: int     = Form(None),
    low_days: int        = Form(None),
    skip_enrichment: bool = Form(False),   # set True to skip external API calls
    ver_opts: dict = Depends(ver_options),
):
    if not file.filename.endswith(".csv"):
        raise HTTPException(400, "Only CSV files are supported.")

    contents = await file.read()
    try:
        df_raw = pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(400, f"Could not parse CSV: {e}")

    # ── Vendor detection ────────────────────────────────────────────────────
    vendor = detect_vendor(df_raw) if vendor_override == "Auto Detect" else vendor_override
    if vendor == "Unknown":
        raise HTTPException(400, "Could not detect vendor format. Try setting vendor_override.")

    # ── Profile resolution ──────────────────────────────────────────────────
    if profile_name == "Custom":
        profile = {
            "Critical": critical_days or 30,
            "High":     high_days     or 30,
            "Medium":   medium_days   or 90,
            "Low":      low_days      or 180,
        }
    else:
        profile = COMPLIANCE_PROFILES.get(profile_name, COMPLIANCE_PROFILES["FedRAMP Moderate/High"])

    # ── Core pipeline ───────────────────────────────────────────────────────
    df_norm, missing_cols = normalize_data(df_raw, vendor)
    df = clean_and_enrich(df_norm, profile)

    # ── CVE intelligence enrichment (KEV / EPSS / NVD) ─────────────────────
    enrichment_errors: list[str] = []
    if not skip_enrichment:
        try:
            df = await enrich_with_cve_intel(df)
        except Exception as exc:
            enrichment_errors.append(str(exc))

    # ── FedRAMP 2026 evaluation (no-op for the severity-based profiles) ─────
    df, ver = apply_profile(df, profile_name, ver_opts)

    # ── Risk-based prioritization ───────────────────────────────────────────
    df = compute_priority(df)

    # ── Metrics ─────────────────────────────────────────────────────────────
    metrics = generate_metrics(df)
    if "kev_listed" in df.columns:
        metrics["kev"] = int(df["kev_listed"].sum())
    metrics["tiers"] = priority_summary(df)
    score, rating = calculate_fleet_risk(df, metrics)

    return JSONResponse({
        "vendor":            vendor,
        "profile_name":      profile_name,
        "profile":           ver["timeframes"] if ver else profile,
        "ver":               ver,
        "metrics":           metrics,
        "risk":              {"score": score, "rating": rating},
        "remediation_plan":  build_remediation_plan(df, top_n=12),
        "missing_columns":   missing_cols,
        "enrichment_errors": enrichment_errors,
        "vulnerabilities":   df_to_records(df),
    })
