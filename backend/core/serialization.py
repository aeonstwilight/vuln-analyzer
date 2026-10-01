"""
serialization.py
----------------
One JSON-safe DataFrame -> records converter, shared by every router.

This exists because `df.where(pd.notna(df), None)` is not a reliable NaN->None
conversion. Under pandas 3.x the new `str` dtype keeps NaN in place rather than
accepting None, and `json.dumps` rejects it with "Out of range float values are
not JSON compliant". That bites whenever a text column is missing a value —
including the literal string "N/A", which read_csv treats as NaN by default.

Conversion is driven by dtype rather than a hardcoded column list, so new
columns (priority scores, CVE intel, whatever comes next) are handled without
anyone having to remember to update a set.
"""

from __future__ import annotations

import math

import numpy as np
import pandas as pd


def _clean_scalar(v):
    """Coerce a single value to something json.dumps will accept."""
    if v is None or v is pd.NaT:
        return None
    if isinstance(v, np.bool_):
        return bool(v)
    if isinstance(v, np.integer):
        return int(v)
    if isinstance(v, (float, np.floating)):
        f = float(v)
        return f if math.isfinite(f) else None
    if isinstance(v, np.ndarray):
        return [_clean_scalar(x) for x in v.tolist()]
    try:
        if pd.isna(v):
            return None
    except (TypeError, ValueError):
        pass  # arrays / lists reach here; they are already handled above
    return v


def df_to_records(df: pd.DataFrame) -> list[dict]:
    """
    Serialise a DataFrame to a list of JSON-safe dicts.

    Datetimes become "YYYY-MM-DD HH:MM:SS" strings, NaT/NaN/inf become None,
    and numpy scalars become native Python types.
    """
    if df.empty:
        return []

    out = df.copy()

    for col in out.columns:
        s = out[col]
        if pd.api.types.is_datetime64_any_dtype(s):
            out[col] = s.dt.strftime("%Y-%m-%d %H:%M:%S").astype(object).where(s.notna(), None)
        elif pd.api.types.is_bool_dtype(s):
            out[col] = s.fillna(False).astype(bool)

    # astype(object) first: only an object column will actually hold None.
    out = out.astype(object).where(pd.notna(out), None)

    return [{k: _clean_scalar(v) for k, v in rec.items()}
            for rec in out.to_dict(orient="records")]
