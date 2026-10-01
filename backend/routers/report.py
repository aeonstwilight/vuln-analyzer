import io
import json
import sys
import os
import uuid
from datetime import datetime, timezone

import pandas as pd
from fastapi import APIRouter, Depends, File, UploadFile, Form, HTTPException
from fastapi.responses import StreamingResponse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import (
    detect_vendor, normalize_data, clean_and_enrich,
    generate_metrics, COMPLIANCE_PROFILES,
    enrich_with_cve_intel,
    compute_priority, calculate_fleet_risk, priority_summary,
    df_to_records, apply_profile, detail_report, is_ver_profile,
)
from .options import ver_options

router = APIRouter(prefix="/report", tags=["report"])


async def _load_and_analyze(
    contents: bytes,
    vendor_override: str,
    profile_name: str,
    critical_days: int = None,
    high_days: int = None,
    medium_days: int = None,
    low_days: int = None,
    ver_opts: dict = None,
):
    """
    Run the exact same pipeline as /analyze so exports and the dashboard agree.

    Any divergence here shows up as a report that contradicts the screen the
    user just looked at, so this must stay in lockstep with routers/analyze.py.
    """
    try:
        df_raw = pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(400, f"Could not parse CSV: {e}")

    vendor = detect_vendor(df_raw) if vendor_override == "Auto Detect" else vendor_override
    if vendor == "Unknown":
        raise HTTPException(400, "Could not detect vendor format.")

    if profile_name == "Custom":
        profile = {
            "Critical": critical_days or 30,
            "High":     high_days     or 30,
            "Medium":   medium_days   or 90,
            "Low":      low_days      or 180,
        }
    else:
        profile = COMPLIANCE_PROFILES.get(profile_name, COMPLIANCE_PROFILES["FedRAMP Moderate/High"])

    df_norm, missing = normalize_data(df_raw, vendor)
    df = clean_and_enrich(df_norm, profile)

    # CVE intelligence (KEV / EPSS / NVD). Without it `compute_priority` falls
    # back to the vendor exploit flag and scores materially lower, so a network
    # failure degrades the export rather than failing the download.
    enrichment_errors: list[str] = []
    try:
        df = await enrich_with_cve_intel(df)
    except Exception as exc:
        enrichment_errors.append(str(exc))

    df, ver = apply_profile(df, profile_name, ver_opts)
    if ver:
        profile = ver["timeframes"]

    df = compute_priority(df)
    metrics = generate_metrics(df)
    if "kev_listed" in df.columns:
        metrics["kev"] = int(df["kev_listed"].sum())
    metrics["tiers"] = priority_summary(df)
    score, rating = calculate_fleet_risk(df, metrics)
    return df, metrics, score, rating, vendor, profile, missing, enrichment_errors


@router.post("/pdf")
async def generate_pdf_report(
    file: UploadFile = File(...),
    vendor_override: str = Form("Auto Detect"),
    profile_name: str    = Form("FedRAMP Moderate/High"),
    critical_days: int   = Form(None),
    high_days: int       = Form(None),
    medium_days: int     = Form(None),
    low_days: int        = Form(None),
    ver_opts: dict       = Depends(ver_options),
):
    from report_generator import generate_pdf_report as _gen

    contents = await file.read()
    df, metrics, score, rating, vendor, profile, _, _ = await _load_and_analyze(
        contents, vendor_override, profile_name,
        critical_days, high_days, medium_days, low_days, ver_opts,
    )
    pdf_bytes = _gen(df, metrics, score, rating, profile_name, vendor,
                     scan_filename=file.filename, profile=profile)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=vuln_report.pdf"},
    )


@router.post("/json")
async def generate_json_report(
    file: UploadFile = File(...),
    vendor_override: str = Form("Auto Detect"),
    profile_name: str    = Form("FedRAMP Moderate/High"),
    critical_days: int   = Form(None),
    high_days: int       = Form(None),
    medium_days: int     = Form(None),
    low_days: int        = Form(None),
    ver_opts: dict       = Depends(ver_options),
):
    """Machine-readable JSON export of the full analysis."""
    contents = await file.read()
    df, metrics, score, rating, vendor, profile, missing, enrichment_errors = await _load_and_analyze(
        contents, vendor_override, profile_name,
        critical_days, high_days, medium_days, low_days, ver_opts,
    )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": file.filename,
        "vendor": vendor,
        "profile_name": profile_name,
        "profile_sla_days": profile,
        "metrics": metrics,
        "risk": {"score": score, "rating": rating},
        "missing_columns": missing,
        "enrichment_errors": enrichment_errors,
        "vulnerabilities": df_to_records(df),
    }

    date = datetime.now().strftime("%Y%m%d")
    return StreamingResponse(
        io.BytesIO(json.dumps(payload, indent=2, default=str).encode()),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=vuln_report_{date}.json"},
    )


@router.post("/oscal")
async def generate_oscal_report(
    file: UploadFile = File(...),
    vendor_override: str = Form("Auto Detect"),
    profile_name: str    = Form("FedRAMP Moderate/High"),
    system_name: str     = Form("Information System"),
    critical_days: int   = Form(None),
    high_days: int       = Form(None),
    medium_days: int     = Form(None),
    low_days: int        = Form(None),
    ver_opts: dict       = Depends(ver_options),
):
    """
    OSCAL 1.1.2 Plan of Action and Milestones (POA&M) export.
    Satisfies FedRAMP 20x machine-readable output requirements.
    """
    contents = await file.read()
    df, metrics, score, rating, vendor, profile, _, _ = await _load_and_analyze(
        contents, vendor_override, profile_name,
        critical_days, high_days, medium_days, low_days, ver_opts,
    )

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tool_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, "vulnanalyzer.tool"))
    doc_uuid = str(uuid.uuid4())

    poam_items = []
    for _, row in df.iterrows():
        item_uuid = str(uuid.uuid4())
        milestone_uuid = str(uuid.uuid4())

        # Build remediation deadline from days_left
        try:
            from datetime import timedelta
            days_left = float(row.get("days_left") or 0)
            deadline = (datetime.now(timezone.utc) + timedelta(days=max(days_left, 0)))
            due_date = deadline.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            due_date = now_iso

        props = [
            {"name": "severity",   "ns": "https://fedramp.gov/ns/oscal", "value": str(row.get("severity", ""))},
            {"name": "cvss-score", "ns": "https://fedramp.gov/ns/oscal", "value": str(row.get("cvss", ""))},
            {"name": "plugin-id",  "value": str(row.get("plugin_id", ""))},
            {"name": "asset-id",   "value": str(row.get("host", ""))},
            {"name": "age-days",   "value": str(int(row["age_days"])) if pd.notna(row.get("age_days")) else ""},
            {"name": "sla-expired","value": str(bool(row.get("expired", False))).lower()},
        ]
        if row.get("exploit_available") not in (None, "", float("nan")):
            props.append({"name": "exploit-available", "value": str(row["exploit_available"]).lower()})

        poam_items.append({
            "uuid": item_uuid,
            "title": str(row.get("plugin_name", "Unknown Vulnerability")),
            "description": (
                f"Host: {row.get('host', 'N/A')} | "
                f"Plugin/CVE: {row.get('plugin_id', 'N/A')} | "
                f"CVSS: {row.get('cvss', 'N/A')} | "
                f"First Discovered: {row.get('first_discovered', 'N/A')}"
            ),
            "props": props,
            "origins": [{
                "actors": [{
                    "type": "tool",
                    "actor-uuid": tool_uuid,
                    "title": "VulnAnalyzer",
                }]
            }],
            "status": {"state": "open"},
            "milestones": [{
                "uuid": milestone_uuid,
                "title": "Scheduled Completion",
                "description": (
                    f"Remediate within {row['remediation_days']:g} days per {profile_name}"
                    if pd.notna(row.get("remediation_days"))
                    else f"No fixed timeframe under {profile_name}; remediate during routine operations"
                ),
                "due-date": due_date,
            }],
        })

    oscal_doc = {
        "plan-of-action-and-milestones": {
            "uuid": doc_uuid,
            "metadata": {
                "title": f"VulnAnalyzer POA&M — {system_name}",
                "last-modified": now_iso,
                "version": "1.0.0",
                "oscal-version": "1.1.2",
                "remarks": (
                    f"Generated by VulnAnalyzer from {file.filename} | "
                    f"Vendor: {vendor} | Profile: {profile_name} | "
                    f"Risk: {rating} (score {score})"
                ),
                "roles": [{"id": "prepared-by", "title": "VulnAnalyzer"}],
                "parties": [{
                    "uuid": tool_uuid,
                    "type": "tool",
                    "name": "VulnAnalyzer",
                }],
            },
            "system-id": {
                "identifier-type": "https://ietf.org/rfc/rfc4122",
                "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, system_name)),
            },
            "poam-items": poam_items,
        }
    }

    date = datetime.now().strftime("%Y%m%d")
    return StreamingResponse(
        io.BytesIO(json.dumps(oscal_doc, indent=2, default=str).encode()),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=poam_oscal_{date}.json"},
    )


@router.post("/ver")
async def generate_ver_report(
    file: UploadFile = File(...),
    vendor_override: str = Form("Auto Detect"),
    profile_name: str    = Form("FedRAMP 2026 Class B"),
    ver_opts: dict       = Depends(ver_options),
):
    """
    Vulnerability detail export for the FedRAMP 2026 profiles: one record per
    finding with the fields VER-RPT-VDT asks a provider to report.

    This is a working draft for an analyst, not a submission. The proposed
    values need review, and the export has not been validated against
    FedRAMP's published JSON schema.
    """
    if not is_ver_profile(profile_name):
        raise HTTPException(400, "This export needs one of the FedRAMP 2026 profiles.")

    contents = await file.read()
    df, metrics, score, rating, vendor, profile, _, enrichment_errors = await _load_and_analyze(
        contents, vendor_override, profile_name, ver_opts=ver_opts,
    )

    records = detail_report(df)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": file.filename,
        "vendor": vendor,
        "profile_name": profile_name,
        "timeframes_days": profile,
        "status": "draft: proposed values, pending analyst evaluation",
        "enrichment_errors": enrichment_errors,
        "vulnerabilities": [r for r in records if not r["accepted_vulnerability_required"]],
        "accepted_vulnerability_candidates": [r for r in records if r["accepted_vulnerability_required"]],
    }

    date = datetime.now().strftime("%Y%m%d")
    return StreamingResponse(
        io.BytesIO(json.dumps(payload, indent=2, default=str).encode()),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=ver_detail_{date}.json"},
    )
