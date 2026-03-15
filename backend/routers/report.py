import io
import sys
import os
import pandas as pd
from fastapi import APIRouter, File, UploadFile, Form, HTTPException
from fastapi.responses import StreamingResponse

# Allow importing report_generator from parent dir if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import (
    detect_vendor, normalize_data, clean_and_enrich,
    generate_metrics, calculate_risk, COMPLIANCE_PROFILES
)

router = APIRouter(prefix="/report", tags=["report"])


@router.post("/pdf")
async def generate_report(
    file: UploadFile = File(...),
    vendor_override: str = Form("Auto Detect"),
    profile_name: str    = Form("FedRAMP Moderate/High"),
):
    from report_generator import generate_pdf_report

    contents = await file.read()
    try:
        df_raw = pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(400, f"Could not parse CSV: {e}")

    vendor = detect_vendor(df_raw) if vendor_override == "Auto Detect" else vendor_override
    if vendor == "Unknown":
        raise HTTPException(400, "Could not detect vendor format.")

    profile = COMPLIANCE_PROFILES.get(profile_name, COMPLIANCE_PROFILES["FedRAMP Moderate/High"])
    df_norm, _ = normalize_data(df_raw, vendor)
    df = clean_and_enrich(df_norm, profile)
    metrics = generate_metrics(df)
    score, rating = calculate_risk(metrics)

    pdf_bytes = generate_pdf_report(
        df, metrics, score, rating,
        profile_name, vendor,
        scan_filename=file.filename,
        profile=profile
    )

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=vuln_report.pdf"}
    )
