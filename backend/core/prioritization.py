"""
prioritization.py
-----------------
Risk-based prioritization: turns a list of findings into a ranked answer to
"what do we fix first?"

Severity alone is a poor ordering. A CVSS 9.8 that nobody has ever weaponised
is less urgent than a CVSS 7.5 that CISA lists as actively exploited and that
sits on 40% of the fleet. This module scores each finding 0-100 across four
weighted factors:

    threat    (40%)  Is anyone actually exploiting this?  KEV > EPSS > exploit flag
    severity  (25%)  How bad is it if they do?            CVSS / 10
    exposure  (20%)  How much of the fleet does it touch? affected hosts / total
    urgency   (15%)  How much SLA runway is left?         days_left vs the window

Every factor is a 0-1 ratio, so the composite is independent of scan size:
a 5-host scan and a 5,000-host scan are scored on the same footing.

The module degrades gracefully. If enrichment was skipped or the external APIs
were unreachable, the KEV/EPSS columns simply won't exist and `threat` falls
back to the vendor's own exploit-available flag. Nothing raises.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# ── factor weights (must sum to 1.0) ───────────────────────────────────────
W_THREAT   = 0.40
W_SEVERITY = 0.25
W_EXPOSURE = 0.20
W_URGENCY  = 0.15

# ── tier cut-offs on the 0-100 priority score ──────────────────────────────
TIER_IMMEDIATE = 65
TIER_URGENT    = 45
TIER_SCHEDULED = 25

TIERS = ["Immediate", "Urgent", "Scheduled", "Routine"]

# Credit given to a vendor "exploit available" flag when we have no EPSS score.
# Deliberately below the KEV value of 1.0 — a public PoC is weaker evidence
# than CISA confirming in-the-wild exploitation.
_EXPLOIT_FLAG_THREAT = 0.35

# Values that mean "no exploit" in the exploit_available column across vendors.
# Anything else (including a numeric exploit count from Rapid7) counts as yes.
_FALSY = {"", "nan", "none", "null", "false", "no", "n", "0", "0.0", "-"}


# ── small helpers ──────────────────────────────────────────────────────────

def _num_col(df: pd.DataFrame, name: str, default: float) -> pd.Series:
    """Numeric column as a float Series, or a constant Series if absent."""
    if name not in df.columns:
        return pd.Series(float(default), index=df.index, dtype=float)
    return pd.to_numeric(df[name], errors="coerce").fillna(default).astype(float)


def _bool_col(df: pd.DataFrame, name: str) -> pd.Series:
    """Boolean column, or an all-False Series if absent."""
    if name not in df.columns:
        return pd.Series(False, index=df.index, dtype=bool)
    return df[name].fillna(False).astype(bool)


def _exploit_flag(df: pd.DataFrame) -> pd.Series:
    """Vendor exploit-available column normalised to bool across formats."""
    if "exploit_available" not in df.columns:
        return pd.Series(False, index=df.index, dtype=bool)
    return ~df["exploit_available"].astype(str).str.strip().str.lower().isin(_FALSY)


# ── the four factors ───────────────────────────────────────────────────────

def _threat(df: pd.DataFrame) -> pd.Series:
    """
    0-1 likelihood that this finding gets exploited.

    CISA KEV is definitive (1.0). Otherwise take the stronger of the EPSS
    probability and the vendor's exploit-available flag.
    """
    kev  = _bool_col(df, "kev_listed")
    epss = _num_col(df, "epss_score", 0.0).clip(0.0, 1.0)
    expl = _exploit_flag(df)

    fallback = np.maximum(epss.to_numpy(), np.where(expl, _EXPLOIT_FLAG_THREAT, 0.0))
    return pd.Series(np.where(kev, 1.0, fallback), index=df.index)


def _severity(df: pd.DataFrame) -> pd.Series:
    """0-1 technical impact, straight off CVSS."""
    return (_num_col(df, "cvss", 0.0) / 10.0).clip(0.0, 1.0)


def _exposure(df: pd.DataFrame) -> pd.Series:
    """
    0-1 blast radius: how much of the fleet carries this same finding.

    sqrt-softened so that going from 1 host to 5 matters more than going from
    100 to 500 — the first few hosts carry most of the signal.
    """
    if "host" not in df.columns or "plugin_id" not in df.columns:
        return pd.Series(0.0, index=df.index)

    total_hosts = max(int(df["host"].nunique()), 1)
    affected = df.groupby("plugin_id")["host"].transform("nunique").astype(float)
    return np.sqrt((affected / total_hosts).clip(0.0, 1.0))


def _urgency(df: pd.DataFrame) -> pd.Series:
    """
    0-1 SLA pressure.

    Inside the window it ramps 0 -> 0.7 as the deadline approaches. Past the
    deadline it starts at 0.7 and climbs to 1.0 over 90 further days, so a
    finding that blew its SLA a year ago outranks one that blew it yesterday.
    A passed CISA KEV due date floors urgency at 0.9 regardless.
    """
    window = _num_col(df, "remediation_days", 90.0).replace(0.0, 90.0)

    # Unknown discovery date -> assume freshly found rather than inventing urgency.
    if "days_left" in df.columns:
        days_left = pd.to_numeric(df["days_left"], errors="coerce").fillna(window)
    else:
        days_left = window.copy()

    overdue = (-days_left).clip(lower=0.0)
    inside  = (0.7 * (1.0 - days_left / window)).clip(0.0, 0.7)
    past    = 0.7 + 0.3 * (overdue / 90.0).clip(0.0, 1.0)

    urgency = pd.Series(np.where(days_left < 0, past, inside), index=df.index)

    # CISA gives its own binding deadline; a missed one overrides the local SLA.
    if "kev_due_date" in df.columns:
        due = pd.to_datetime(df["kev_due_date"], errors="coerce")
        missed = due.notna() & (due < pd.Timestamp.today().normalize())
        urgency = urgency.mask(missed, urgency.clip(lower=0.9))

    return urgency


# ── reason strings ─────────────────────────────────────────────────────────

def _reasons(df: pd.DataFrame, exposure: pd.Series) -> pd.Series:
    """
    Short human explanation of why each finding ranks where it does.

    A ranked list nobody trusts is a ranked list nobody uses, so every row
    carries the evidence that drove it.
    """
    kev      = _bool_col(df, "kev_listed")
    epss     = _num_col(df, "epss_score", 0.0)
    expl     = _exploit_flag(df)
    expired  = _bool_col(df, "expired")
    days_left = _num_col(df, "days_left", 999.0)
    total_hosts = max(int(df["host"].nunique()), 1) if "host" in df.columns else 1
    affected = (
        df.groupby("plugin_id")["host"].transform("nunique")
        if "host" in df.columns and "plugin_id" in df.columns
        else pd.Series(1, index=df.index)
    )

    out = []
    for i in df.index:
        bits = []
        if kev.at[i]:
            bits.append("Actively exploited (CISA KEV)")
        if epss.at[i] >= 0.10:
            bits.append(f"EPSS {epss.at[i] * 100:.0f}% exploit probability")
        elif not kev.at[i] and expl.at[i]:
            bits.append("Public exploit available")

        if expired.at[i]:
            bits.append(f"SLA expired {abs(int(days_left.at[i]))}d ago")
        elif days_left.at[i] <= 14:
            bits.append(f"SLA due in {int(days_left.at[i])}d")

        n = int(affected.at[i])
        if n > 1:
            pct = n / total_hosts * 100
            bits.append(f"Affects {n} hosts ({pct:.0f}% of fleet)")

        if not bits:
            bits.append("Severity-driven; no active exploit signal")
        out.append(" · ".join(bits))

    return pd.Series(out, index=df.index)


# ── public API ─────────────────────────────────────────────────────────────

def compute_priority(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add prioritization columns to `df` and return the copy:

      priority_score   float 0-100, the composite ranking value
      priority_tier    Immediate | Urgent | Scheduled | Routine
      priority_reason  human-readable explanation of the drivers
      factor_threat    0-1 component scores, kept so the UI can show a breakdown
      factor_severity  0-1
      factor_exposure  0-1
      factor_urgency   0-1
      hosts_affected   int, hosts carrying this same plugin_id
    """
    df = df.copy()
    if df.empty:
        for col in ("priority_score", "factor_threat", "factor_severity",
                    "factor_exposure", "factor_urgency"):
            df[col] = pd.Series(dtype=float)
        df["priority_tier"] = pd.Series(dtype=str)
        df["priority_reason"] = pd.Series(dtype=str)
        df["hosts_affected"] = pd.Series(dtype=int)
        return df

    threat   = _threat(df)
    severity = _severity(df)
    exposure = _exposure(df)
    urgency  = _urgency(df)

    score = 100.0 * (
        W_THREAT   * threat
        + W_SEVERITY * severity
        + W_EXPOSURE * exposure
        + W_URGENCY  * urgency
    )

    df["factor_threat"]   = threat.round(4)
    df["factor_severity"] = severity.round(4)
    df["factor_exposure"] = exposure.round(4)
    df["factor_urgency"]  = urgency.round(4)
    df["priority_score"]  = score.round(1)

    df["priority_tier"] = pd.cut(
        df["priority_score"],
        bins=[-0.01, TIER_SCHEDULED, TIER_URGENT, TIER_IMMEDIATE, 100.01],
        labels=["Routine", "Scheduled", "Urgent", "Immediate"],
    ).astype(str)

    if "host" in df.columns and "plugin_id" in df.columns:
        df["hosts_affected"] = df.groupby("plugin_id")["host"].transform("nunique").astype(int)
    else:
        df["hosts_affected"] = 1

    df["priority_reason"] = _reasons(df, exposure)
    return df


def build_remediation_plan(df: pd.DataFrame, top_n: int = 12) -> list[dict]:
    """
    Collapse findings into distinct remediation *actions*.

    The same plugin across 40 hosts is one patch, not 40 tickets. Grouping by
    plugin turns a 900-row table into a short list of things a human can
    actually schedule, ordered by the worst finding each action clears.
    """
    if df.empty or "priority_score" not in df.columns:
        return []

    group_key = "plugin_id" if "plugin_id" in df.columns else "plugin_name"
    if group_key not in df.columns:
        return []

    plan: list[dict] = []
    for key, g in df.groupby(group_key, dropna=False):
        top = g.loc[g["priority_score"].idxmax()]
        hosts = sorted({str(h) for h in g.get("host", pd.Series(dtype=str)).dropna()})
        plan.append({
            "plugin_id":      str(key),
            "plugin_name":    str(top.get("plugin_name") or key),
            "cve_id":         str(top.get("cve_id") or ""),
            "severity":       str(top.get("severity") or ""),
            "priority_score": float(top["priority_score"]),
            "priority_tier":  str(top.get("priority_tier") or ""),
            "kev_listed":     bool(top.get("kev_listed", False)),
            "epss_score":     float(top.get("epss_score") or 0.0),
            "findings":       int(len(g)),
            "hosts_affected": len(hosts),
            "hosts":          hosts[:10],
            "expired":        int(g.get("expired", pd.Series(False, index=g.index)).sum()),
            "solution":       str(top.get("solution") or "").strip(),
            "reason":         str(top.get("priority_reason") or ""),
        })

    # Worst finding first; ties broken by how many hosts the one fix clears.
    plan.sort(key=lambda r: (r["priority_score"], r["hosts_affected"]), reverse=True)
    return plan[:top_n]


def calculate_fleet_risk(df: pd.DataFrame, metrics: dict) -> tuple[int, str]:
    """
    Fleet risk as a 0-100 score, independent of how many rows the CSV had.

    Three ratios, so a big scan is not automatically a worse scan:
      peak       (55%)  mean priority of the worst decile of findings
      kev_spread (25%)  share of hosts carrying at least one KEV finding
      sla_debt   (20%)  share of findings past their remediation deadline

    `peak` is a decile rather than a fixed "top 10" on purpose: a fixed count
    dilutes small scans with their own low-severity rows, so the same findings
    duplicated across a larger fleet would score differently.
    """
    if df.empty or "priority_score" not in df.columns:
        return 0, "Low"

    scores = df["priority_score"].dropna().sort_values(ascending=False)
    if scores.empty:
        return 0, "Low"
    decile = max(1, -(-len(scores) // 10))       # ceil(n / 10), at least one
    peak = float(scores.head(decile).mean())

    total_hosts = max(int(df["host"].nunique()), 1) if "host" in df.columns else 1
    if "kev_listed" in df.columns and "host" in df.columns:
        kev_hosts = int(df.loc[_bool_col(df, "kev_listed"), "host"].nunique())
    else:
        kev_hosts = 0
    kev_spread = kev_hosts / total_hosts

    total = max(int(metrics.get("total", len(df))), 1)
    sla_debt = int(metrics.get("expired", 0)) / total

    score = 0.55 * peak + 25.0 * kev_spread + 20.0 * sla_debt
    score = int(round(min(score, 100.0)))

    if score < 25:
        rating = "Low"
    elif score < 45:
        rating = "Moderate"
    elif score < 70:
        rating = "High"
    else:
        rating = "Severe"
    return score, rating


def priority_summary(df: pd.DataFrame) -> dict:
    """Tier counts, for the metric cards."""
    if df.empty or "priority_tier" not in df.columns:
        return {t: 0 for t in TIERS}
    counts = df["priority_tier"].value_counts().to_dict()
    return {t: int(counts.get(t, 0)) for t in TIERS}
