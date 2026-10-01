"""
fedramp2026.py
--------------
First-pass vulnerability evaluation under the FedRAMP Consolidated Rules for
2026 (Vulnerability Evaluation and Reporting, VER, and Vulnerability Detection
and Response, VDR).

The pre-2026 model was a deadline per scanner severity: High in 30 days,
Moderate in 90, Low in 180. The 2026 rules replace that with three questions
asked of every finding (VER-EVA):

    LEV   Is it a likely exploitable vulnerability?
    IRV   Is it an internet-reachable vulnerability?
    PAIN  What is the Potential Agency Impact N-rating, N1 to N5?

and a deadline that depends on all three plus the Certification Class
(VDR-TFR-PVR). A scanner export cannot answer the second and third questions,
so this module takes an optional asset context file (which hosts can be
reached from the internet, and how bad compromise of each would be for agency
customers) and is explicit about what it assumed where that file is silent.

Everything here is a *proposal for an analyst to confirm*. The rules require
the provider to evaluate each vulnerability in the context of the cloud
service offering; no heuristic over a CSV does that. Each proposed value
carries a `*_basis` column saying where it came from.

Deadlines are counted from first discovery. The rules count from completed
evaluation, which a scan export does not record, so discovery is used as the
earlier and therefore stricter anchor.

Rules as published at https://www.fedramp.gov/2026/ on 2026-10-01.
"""

from __future__ import annotations

import io
import ipaddress
from fnmatch import fnmatchcase

import numpy as np
import pandas as pd

from .prioritization import _bool_col, _exploit_flag, _num_col

# ── profiles ───────────────────────────────────────────────────────────────
# Rev5 Certifications are Class B, C or D.
VER_PROFILES = {
    "FedRAMP 2026 Class B": "B",
    "FedRAMP 2026 Class C": "C",
    "FedRAMP 2026 Class D": "D",
}

# VDR-TFR-PVR: days to reduce the Potential Agency Impact N-rating.
# {class: {PAIN: (LEV + IRV, LEV + not IRV, not LEV)}}
# PAIN 1 has no timeframe; VDR-TFR-RMN leaves it to routine operations.
PVR_DAYS = {
    "B": {5: (4, 8, 32),   4: (8, 32, 64), 3: (32, 64, 192), 2: (96, 160, 192)},
    "C": {5: (2, 4, 16),   4: (4, 8, 64),  3: (16, 32, 128), 2: (48, 128, 192)},
    "D": {5: (0.5, 1, 8),  4: (2, 8, 32),  3: (8, 16, 64),   2: (24, 96, 192)},
}

# VER-TFR-MAV: anything not fully mitigated or remediated within 192 days of
# evaluation must be categorized as an accepted vulnerability.
ACCEPT_AFTER_DAYS = 192

# Highest N-rating a finding of each scanner severity is proposed at. The
# asset's own impact ceiling can lower this, never raise it.
_SEVERITY_CAP = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2}

DEFAULT_IMPACT = 3
DEFAULT_EPSS_THRESHOLD = 0.10

_TRUTHY = {"yes", "y", "true", "1", "internet", "public", "external"}


def is_ver_profile(profile_name: str) -> bool:
    return profile_name in VER_PROFILES


def timeframes(cert_class: str) -> dict[str, float]:
    """Flat {label: days} view of one class's PVR table, for display."""
    out = {}
    for pain in (5, 4, 3, 2):
        lev_irv, lev_nirv, nlev = PVR_DAYS[cert_class][pain]
        out[f"N{pain} likely exploitable, internet-reachable"] = lev_irv
        out[f"N{pain} likely exploitable, not internet-reachable"] = lev_nirv
        out[f"N{pain} not likely exploitable"] = nlev
    return out


# ── asset context ──────────────────────────────────────────────────────────

def load_asset_context(contents: bytes) -> pd.DataFrame:
    """
    Parse an asset context CSV.

    Required column:  host               exact name or IP, a CIDR range, or a * wildcard
    Optional columns: internet_reachable yes / no
                      impact             1-5 or N1-N5: worst effect on agency customers
                                         if this asset were compromised
    """
    df = pd.read_csv(io.BytesIO(contents), dtype=str).fillna("")
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")
    if "host" not in df.columns:
        raise ValueError("Asset context CSV needs a 'host' column.")

    out = pd.DataFrame({"host": df["host"].str.strip()})
    out = out[out["host"] != ""].copy()

    if "internet_reachable" in df.columns:
        raw = df.loc[out.index, "internet_reachable"].str.strip().str.lower()
        out["internet_reachable"] = raw.map(lambda v: None if v == "" else v in _TRUTHY)
    else:
        out["internet_reachable"] = None

    if "impact" in df.columns:
        raw = df.loc[out.index, "impact"].str.strip().str.upper().str.lstrip("N")
        impact = pd.to_numeric(raw, errors="coerce")
        if ((impact < 1) | (impact > 5)).any():
            raise ValueError("Asset context 'impact' must be between 1 and 5 (or N1 to N5).")
        out["impact"] = impact
    else:
        out["impact"] = np.nan

    return out.reset_index(drop=True)


def _match_host(host: str, context: pd.DataFrame):
    """Most specific matching context row for a host: exact, then CIDR, then wildcard."""
    host_l = host.lower()
    exact = cidr = glob = None
    for row in context.itertuples(index=False):
        pattern = row.host.lower()
        if pattern == host_l:
            exact = row
            break
        if "/" in pattern and cidr is None:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False):
                    cidr = row
            except ValueError:
                pass
        elif "*" in pattern and glob is None and fnmatchcase(host_l, pattern):
            glob = row
    return exact or cidr or glob


# ── the three evaluations ──────────────────────────────────────────────────

def _evaluate_lev(df: pd.DataFrame, epss_threshold: float) -> tuple[pd.Series, pd.Series]:
    """
    Likely exploitable (VER-EVA-ELX).

    FedRAMP declines to prescribe a framework, so this uses the evidence the
    pipeline already has: CISA KEV, then EPSS at or above the threshold, then
    the scanner's own exploit-available flag. If CVE intelligence could not be
    fetched at all, the finding is assumed likely exploitable: reporting "not
    likely" with no evidence is the outcome the rule warns against.
    """
    has_intel = "kev_listed" in df.columns or "epss_score" in df.columns
    kev = _bool_col(df, "kev_listed")
    epss = _num_col(df, "epss_score", 0.0)
    flag = _exploit_flag(df)

    lev, basis = [], []
    for i in df.index:
        if kev.at[i]:
            lev.append(True)
            basis.append("Listed in CISA KEV")
        elif epss.at[i] >= epss_threshold:
            lev.append(True)
            basis.append(f"EPSS {epss.at[i] * 100:.0f}% is at or above the {epss_threshold * 100:.0f}% threshold")
        elif flag.at[i]:
            lev.append(True)
            basis.append("Scanner reports an available exploit")
        elif not has_intel:
            lev.append(True)
            basis.append("Assumed: exploit intelligence was unavailable")
        else:
            lev.append(False)
            basis.append("No exploitation evidence in KEV, EPSS or scanner data")
    return pd.Series(lev, index=df.index, dtype=bool), pd.Series(basis, index=df.index)


def _evaluate_context(
    df: pd.DataFrame,
    context: pd.DataFrame | None,
    assume_reachable: bool,
    default_impact: int,
) -> pd.DataFrame:
    """Internet reachability (VER-EVA-EIR) and the impact ceiling per host."""
    hosts = df["host"].astype(str) if "host" in df.columns else pd.Series("", index=df.index)
    lookup = {}
    for host in hosts.unique():
        match = _match_host(host, context) if context is not None and len(context) else None
        reachable = match.internet_reachable if match is not None else None
        impact = match.impact if match is not None else np.nan

        if reachable is None or pd.isna(reachable):
            irv, irv_basis = assume_reachable, "Assumed: host not in asset context"
        else:
            irv, irv_basis = bool(reachable), f"Asset context ({match.host})"

        if pd.isna(impact):
            ceiling, ceiling_basis = default_impact, f"default N{default_impact}"
        else:
            ceiling, ceiling_basis = int(impact), f"asset context N{int(impact)}"

        lookup[host] = (irv, irv_basis, ceiling, ceiling_basis)

    cols = hosts.map(lookup)
    return pd.DataFrame(cols.tolist(), index=df.index,
                        columns=["irv", "irv_basis", "ceiling", "ceiling_basis"])


def _evaluate_pain(df: pd.DataFrame, ctx: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    """
    Potential Agency Impact N-rating (VER-EVA-EPA).

    Proposed as the lower of two limits: how bad compromise of the asset would
    be for agency customers, and how much of that a finding of this severity
    could plausibly deliver. Findings with no CVSS score are proposed at N1.
    """
    severity = df["severity"] if "severity" in df.columns else pd.Series("Low", index=df.index)
    cvss = _num_col(df, "cvss", 0.0)
    cap = severity.map(_SEVERITY_CAP).fillna(2).astype(int).where(cvss > 0, 1)

    pain = np.minimum(cap, ctx["ceiling"].astype(int))
    basis = [
        f"Lower of asset impact ({ctx.at[i, 'ceiling_basis']}) and severity cap (N{cap.at[i]})"
        for i in df.index
    ]
    return pd.Series(pain, index=df.index).astype(int), pd.Series(basis, index=df.index)


def _due_days(cert_class: str, pain: pd.Series, lev: pd.Series, irv: pd.Series) -> pd.Series:
    table = PVR_DAYS[cert_class]
    out = []
    for i in pain.index:
        row = table.get(int(pain.at[i]))
        if row is None:
            out.append(np.nan)
        elif not lev.at[i]:
            out.append(row[2])
        else:
            out.append(row[0] if irv.at[i] else row[1])
    return pd.Series(out, index=pain.index, dtype=float)


def _incident(cert_class: str, pain: pd.Series, lev: pd.Series, irv: pd.Series) -> pd.Series:
    """
    Whether the rules say to treat the finding as a FedRAMP Reportable Incident
    until it is mitigated to a lower rating. "should" or "may" is the strength
    the rule uses for this class; "" means neither rule applies.
    """
    internet = lev & irv & (pain > 3)                 # VER-TFR-IRI
    internal = lev & ~irv & (pain == 5)               # VER-TFR-NRI
    internet_word = "should" if cert_class in ("C", "D") else "may"
    internal_word = "should" if cert_class == "D" else "may"
    out = pd.Series("", index=pain.index)
    out = out.mask(internal, internal_word)
    return out.mask(internet, internet_word)


# ── public API ─────────────────────────────────────────────────────────────

def evaluate(
    df: pd.DataFrame,
    cert_class: str,
    asset_context: pd.DataFrame | None = None,
    assume_reachable: bool = False,
    default_impact: int = DEFAULT_IMPACT,
    epss_threshold: float = DEFAULT_EPSS_THRESHOLD,
) -> pd.DataFrame:
    """
    Add the 2026 evaluation columns and return the copy:

      ver_lev / ver_lev_basis    likely exploitable, and why
      ver_irv / ver_irv_basis    internet-reachable, and where that came from
      ver_pain / ver_pain_basis  proposed N-rating 1-5, and how it was derived
      ver_due_days               timeframe for this class, NaN at N1
      ver_accept_required        older than 192 days: must be reported as accepted
      ver_incident               "should" / "may" / "" (reportable-incident rules)

    `remediation_days`, `days_left` and `expired` are overwritten with the
    2026 values so prioritization, metrics and every export work unchanged.
    """
    if cert_class not in PVR_DAYS:
        raise ValueError(f"Unknown Certification Class: {cert_class}")
    default_impact = int(min(max(default_impact, 1), 5))

    df = df.copy()
    lev, lev_basis = _evaluate_lev(df, epss_threshold)
    ctx = _evaluate_context(df, asset_context, assume_reachable, default_impact)
    irv = ctx["irv"].astype(bool)
    pain, pain_basis = _evaluate_pain(df, ctx)
    due = _due_days(cert_class, pain, lev, irv)
    age = _num_col(df, "age_days", np.nan)

    df["ver_lev"] = lev
    df["ver_lev_basis"] = lev_basis
    df["ver_irv"] = irv
    df["ver_irv_basis"] = ctx["irv_basis"]
    df["ver_pain"] = pain
    df["ver_pain_basis"] = pain_basis
    df["ver_due_days"] = due
    df["ver_accept_required"] = (age > ACCEPT_AFTER_DAYS).fillna(False)
    df["ver_incident"] = _incident(cert_class, pain, lev, irv)

    df["remediation_days"] = due
    df["days_left"] = (due - age).round(1)
    df["expired"] = (df["days_left"] < 0).fillna(False)
    return df


def apply_profile(df: pd.DataFrame, profile_name: str, options: dict | None = None):
    """
    Run the 2026 evaluation when `profile_name` is one of VER_PROFILES.

    Returns (df, summary). For any other profile the frame is returned
    untouched with a summary of None, so callers need no branching.
    """
    if not is_ver_profile(profile_name):
        return df, None
    options = options or {}
    cert_class = VER_PROFILES[profile_name]
    context = options.get("asset_context")
    df = evaluate(
        df, cert_class,
        asset_context=context,
        assume_reachable=bool(options.get("assume_reachable", False)),
        default_impact=options.get("default_impact", DEFAULT_IMPACT),
        epss_threshold=options.get("epss_threshold", DEFAULT_EPSS_THRESHOLD),
    )
    return df, summarize(df, cert_class, context)


def summarize(df: pd.DataFrame, cert_class: str, asset_context: pd.DataFrame | None) -> dict:
    """Counts for the dashboard, plus what was assumed so the reader can judge them."""
    assumed_hosts = (
        int(df.loc[df["ver_irv_basis"].str.startswith("Assumed"), "host"].nunique())
        if "host" in df.columns else 0
    )
    return {
        "class": cert_class,
        "timeframes": timeframes(cert_class),
        "likely_exploitable": int(df["ver_lev"].sum()),
        "internet_reachable": int(df["ver_irv"].sum()),
        "lev_and_irv": int((df["ver_lev"] & df["ver_irv"]).sum()),
        "pain": {f"N{n}": int((df["ver_pain"] == n).sum()) for n in (5, 4, 3, 2, 1)},
        "overdue": int(df["expired"].sum()),
        "accept_required": int(df["ver_accept_required"].sum()),
        "incident_should": int((df["ver_incident"] == "should").sum()),
        "incident_may": int((df["ver_incident"] == "may").sum()),
        "asset_context_rows": 0 if asset_context is None else int(len(asset_context)),
        "hosts_with_assumed_reachability": assumed_hosts,
    }


def detail_report(df: pd.DataFrame) -> list[dict]:
    """
    One record per finding carrying the fields VER-RPT-VDT asks a provider to
    report. Fields a scan cannot supply (completed evaluation time, rating
    history, final disposition) are present and empty for the analyst to fill.
    """
    records = []
    for _, row in df.iterrows():
        first = row.get("first_discovered")
        due = row.get("ver_due_days")
        records.append({
            "tracking_id": f"{row.get('host', '')}:{row.get('plugin_id', '')}",
            "title": str(row.get("plugin_name") or ""),
            "cve": str(row.get("cve_id") or ""),
            "detected_at": first.isoformat() if pd.notna(first) else None,
            "detection_source": "vulnerability scan",
            "evaluated_at": None,
            "internet_reachable": bool(row["ver_irv"]),
            "internet_reachable_basis": row["ver_irv_basis"],
            "likely_exploitable": bool(row["ver_lev"]),
            "likely_exploitable_basis": row["ver_lev_basis"],
            "potential_agency_impact": f"N{int(row['ver_pain'])}",
            "potential_agency_impact_basis": row["ver_pain_basis"],
            "potential_agency_impact_history": [],
            "timeframe_days": None if pd.isna(due) else float(due),
            "overdue": bool(row.get("expired", False)),
            "accepted_vulnerability_required": bool(row["ver_accept_required"]),
            "known_exploited": bool(row.get("kev_listed", False)),
            "kev_due_date": str(row.get("kev_due_date") or "") or None,
            "reportable_incident": row["ver_incident"] or None,
            "final_disposition": None,
        })
    return records
