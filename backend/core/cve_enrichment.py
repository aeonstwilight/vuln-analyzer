"""
cve_enrichment.py
-----------------
Enriches vulnerability DataFrames with three external intelligence sources:

  1. CISA KEV  – Known Exploited Vulnerabilities catalog (cached 24 h)
  2. EPSS      – Exploit Prediction Scoring System scores (session-cached)
  3. NVD       – National Vulnerability Database descriptions & CWE (session-cached,
                 rate-limited per NIST guidelines)

All network calls are async. The module degrades gracefully: if an API is
unreachable the corresponding columns are left empty rather than crashing.

Environment variables:
  NVD_API_KEY   Optional. Raises NVD rate limit from 5 req/30 s to 50 req/30 s.
  NVD_MAX_CVEs  Optional int, default 30. Max CVE IDs sent to NVD per analysis.
"""

import asyncio
import os
import re
from datetime import datetime, timedelta, timezone

import httpx
import pandas as pd

# ── regex ──────────────────────────────────────────────────────────────────
CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

# ── external endpoints ─────────────────────────────────────────────────────
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── in-process caches ──────────────────────────────────────────────────────
_kev_cache: dict = {}            # {CVE_ID: kev_entry_dict}
_kev_fetched_at: datetime | None = None
_KEV_TTL = timedelta(hours=24)

_epss_cache: dict = {}           # {CVE_ID: {"epss": float, "percentile": float}}
_nvd_cache: dict  = {}           # {CVE_ID: {"nvd_description": str, "cwe": str}}


# ── CVE extraction ─────────────────────────────────────────────────────────

def extract_cve_ids(df: pd.DataFrame) -> list[str]:
    """
    Return a sorted list of unique CVE IDs found anywhere in the DataFrame
    columns: plugin_id, cve_refs (if present), plugin_name.
    """
    sources = [df.get("plugin_id",   pd.Series(dtype=str)).astype(str),
               df.get("cve_refs",    pd.Series(dtype=str)).astype(str),
               df.get("plugin_name", pd.Series(dtype=str)).astype(str)]
    combined = pd.concat(sources, ignore_index=True)
    cves: set[str] = set()
    for val in combined.dropna():
        cves.update(m.upper() for m in CVE_RE.findall(val))
    return sorted(cves)


def _primary_cve(row: pd.Series) -> str:
    """Return the first CVE ID found in a single row, or ''."""
    for col in ("plugin_id", "cve_refs", "plugin_name"):
        val = str(row.get(col, ""))
        m = CVE_RE.search(val)
        if m:
            return m.group(0).upper()
    return ""


# ── CISA KEV ───────────────────────────────────────────────────────────────

async def _fetch_kev_catalog() -> dict:
    """Fetch (and cache) the CISA KEV catalog. Returns {CVE_ID: entry}."""
    global _kev_cache, _kev_fetched_at

    now = datetime.now(timezone.utc)
    if _kev_cache and _kev_fetched_at and (now - _kev_fetched_at) < _KEV_TTL:
        return _kev_cache

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
        _kev_cache = {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}
        _kev_fetched_at = now
    except Exception as exc:
        print(f"[cve_enrichment] KEV fetch failed: {exc}")
        _kev_cache = _kev_cache or {}   # keep stale cache if we had one

    return _kev_cache


# ── FIRST EPSS ─────────────────────────────────────────────────────────────

async def _fetch_epss(cve_ids: list[str]) -> dict:
    """
    Batch-fetch EPSS scores for cve_ids.
    EPSS API supports up to ~2 000 CVEs per request.
    Returns {CVE_ID: {"epss": float, "percentile": float}}.
    """
    if not cve_ids:
        return {}

    uncached = [c for c in cve_ids if c not in _epss_cache]
    if uncached:
        BATCH = 1500
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                for i in range(0, len(uncached), BATCH):
                    batch = uncached[i : i + BATCH]
                    params = {"cve": ",".join(batch), "limit": BATCH}
                    resp = await client.get(EPSS_URL, params=params)
                    if resp.status_code == 200:
                        for item in resp.json().get("data", []):
                            cid = item["cve"].upper()
                            _epss_cache[cid] = {
                                "epss":       float(item.get("epss", 0)),
                                "percentile": float(item.get("percentile", 0)),
                            }
        except Exception as exc:
            print(f"[cve_enrichment] EPSS fetch failed: {exc}")

    return {c: _epss_cache[c] for c in cve_ids if c in _epss_cache}


# ── NVD CVE API ────────────────────────────────────────────────────────────

async def _fetch_one_nvd(client: httpx.AsyncClient, cve_id: str) -> None:
    """Fetch a single CVE from NVD and populate _nvd_cache."""
    if cve_id in _nvd_cache:
        return
    try:
        resp = await client.get(NVD_URL, params={"cveId": cve_id})
        if resp.status_code == 200:
            vulns = resp.json().get("vulnerabilities", [])
            if vulns:
                cve_data = vulns[0]["cve"]
                desc = next(
                    (d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"),
                    "",
                )
                weaknesses = cve_data.get("weaknesses", [])
                cwe = ""
                if weaknesses:
                    for wd in weaknesses[0].get("description", []):
                        if wd.get("value", "").startswith("CWE-"):
                            cwe = wd["value"]
                            break
                _nvd_cache[cve_id] = {"nvd_description": desc[:600], "cwe": cwe}
                return
        _nvd_cache[cve_id] = {"nvd_description": "", "cwe": ""}
    except Exception:
        _nvd_cache[cve_id] = {"nvd_description": "", "cwe": ""}


async def _fetch_nvd(cve_ids: list[str], api_key: str | None, max_lookups: int) -> dict:
    """
    Rate-limited NVD fetch.
      Without API key : 5 req / 30 s  → batch of 5, sleep 6.5 s between batches
      With API key    : 50 req / 30 s → batch of 50, sleep 0.7 s between batches
    """
    if not cve_ids:
        return {}

    uncached = [c for c in cve_ids if c not in _nvd_cache][:max_lookups]
    if not uncached:
        return {c: _nvd_cache[c] for c in cve_ids if c in _nvd_cache}

    batch_size = 50 if api_key else 5
    batch_delay = 0.7 if api_key else 6.5

    headers = {"apiKey": api_key} if api_key else {}

    try:
        async with httpx.AsyncClient(timeout=15, headers=headers) as client:
            for i in range(0, len(uncached), batch_size):
                batch = uncached[i : i + batch_size]
                await asyncio.gather(*[_fetch_one_nvd(client, c) for c in batch])
                if i + batch_size < len(uncached):
                    await asyncio.sleep(batch_delay)
    except Exception as exc:
        print(f"[cve_enrichment] NVD fetch failed: {exc}")

    return {c: _nvd_cache[c] for c in cve_ids if c in _nvd_cache}


# ── Main enrichment entry point ────────────────────────────────────────────

async def enrich_with_cve_intel(
    df: pd.DataFrame,
    nvd_api_key: str | None = None,
    nvd_max_lookups: int = 30,
) -> pd.DataFrame:
    """
    Adds the following columns to df (in-place copy):

      cve_id           – first CVE ID matched per row (or '')
      kev_listed       – bool: appears in CISA KEV catalog
      kev_due_date     – CISA mandated due date (str) or ''
      kev_name         – short KEV vulnerability name or ''
      epss_score       – float 0–1  probability of exploitation in next 30 days
      epss_percentile  – float 0–1  percentile rank among all scored CVEs
      nvd_description  – English description from NVD (≤ 600 chars)
      cwe              – CWE-XXX identifier from NVD

    All three external API calls run concurrently. Any failure leaves the
    respective columns empty rather than crashing the analysis.
    """
    df = df.copy()

    # Resolve NVD API key from env if not passed explicitly
    if not nvd_api_key:
        nvd_api_key = os.environ.get("NVD_API_KEY") or None
    nvd_max_lookups = int(os.environ.get("NVD_MAX_CVEs", nvd_max_lookups))

    # Assign primary CVE ID per row
    df["cve_id"] = df.apply(_primary_cve, axis=1)

    all_cves = [c for c in df["cve_id"].unique() if c]

    # Prioritise Critical/High CVEs for NVD lookups (limited quota)
    if "severity" in df.columns:
        priority_cves = (
            df[df["severity"].isin(["Critical", "High"])]["cve_id"]
            .dropna()
            .unique()
            .tolist()
        )
        other_cves = [c for c in all_cves if c not in priority_cves]
        nvd_cves = (priority_cves + other_cves)[:nvd_max_lookups]
    else:
        nvd_cves = all_cves[:nvd_max_lookups]

    # Fan out all three fetches concurrently
    kev_data, epss_data, nvd_data = await asyncio.gather(
        _fetch_kev_catalog(),
        _fetch_epss(all_cves),
        _fetch_nvd(nvd_cves, nvd_api_key, nvd_max_lookups),
        return_exceptions=False,
    )

    # Map results back to DataFrame rows
    def _kev_row(cve: str) -> pd.Series:
        e = kev_data.get(cve, {})
        return pd.Series({
            "kev_listed":   bool(e),
            "kev_due_date": e.get("dueDate", ""),
            "kev_name":     e.get("vulnerabilityName", ""),
        })

    def _epss_row(cve: str) -> pd.Series:
        e = epss_data.get(cve, {})
        return pd.Series({
            "epss_score":      e.get("epss", 0.0),
            "epss_percentile": e.get("percentile", 0.0),
        })

    def _nvd_row(cve: str) -> pd.Series:
        e = nvd_data.get(cve, {})
        return pd.Series({
            "nvd_description": e.get("nvd_description", ""),
            "cwe":             e.get("cwe", ""),
        })

    kev_df  = df["cve_id"].apply(_kev_row)
    epss_df = df["cve_id"].apply(_epss_row)
    nvd_df  = df["cve_id"].apply(_nvd_row)

    return pd.concat([df, kev_df, epss_df, nvd_df], axis=1)
