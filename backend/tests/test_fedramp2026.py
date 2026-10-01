"""
Tests for the FedRAMP 2026 evaluation.

Run from the backend folder:  python -m unittest discover tests
"""
import sys
import unittest
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.fedramp2026 import (  # noqa: E402
    ACCEPT_AFTER_DAYS, PVR_DAYS, apply_profile, detail_report, evaluate, load_asset_context,
)

CONTEXT = load_asset_context(
    b"host,internet_reachable,impact\n"
    b"203.0.113.0/24,yes,N4\n"
    b"10.20.1.15,yes,5\n"
    b"10.20.3.*,no,2\n"
)


def finding(**overrides):
    row = {
        "plugin_id": "1", "plugin_name": "Example", "host": "10.20.1.15",
        "cvss": 9.8, "severity": "Critical", "age_days": 1,
        "kev_listed": False, "epss_score": 0.0, "exploit_available": "No",
    }
    row.update(overrides)
    return row


def run(rows, cert_class="C", **kwargs):
    kwargs.setdefault("asset_context", CONTEXT)
    return evaluate(pd.DataFrame(rows), cert_class, **kwargs)


class LikelyExploitable(unittest.TestCase):
    def test_kev_is_likely_exploitable(self):
        out = run([finding(kev_listed=True)])
        self.assertTrue(out.at[0, "ver_lev"])
        self.assertIn("KEV", out.at[0, "ver_lev_basis"])

    def test_epss_threshold_is_inclusive(self):
        out = run([finding(epss_score=0.10), finding(epss_score=0.09)])
        self.assertEqual(out["ver_lev"].tolist(), [True, False])

    def test_scanner_exploit_flag_counts(self):
        self.assertTrue(run([finding(exploit_available="Yes")]).at[0, "ver_lev"])

    def test_no_evidence_is_not_likely(self):
        self.assertFalse(run([finding()]).at[0, "ver_lev"])

    def test_missing_intel_is_assumed_likely(self):
        row = finding()
        del row["kev_listed"], row["epss_score"]
        out = run([row])
        self.assertTrue(out.at[0, "ver_lev"])
        self.assertTrue(out.at[0, "ver_lev_basis"].startswith("Assumed"))


class AssetContext(unittest.TestCase):
    def test_exact_cidr_and_wildcard_matches(self):
        out = run([
            finding(host="10.20.1.15"),
            finding(host="203.0.113.10"),
            finding(host="10.20.3.7"),
        ])
        self.assertEqual(out["ver_irv"].tolist(), [True, True, False])
        self.assertEqual(out["ver_pain"].tolist(), [5, 4, 2])

    def test_unlisted_host_uses_the_stated_assumption(self):
        self.assertFalse(run([finding(host="192.0.2.1")]).at[0, "ver_irv"])
        out = run([finding(host="192.0.2.1")], assume_reachable=True)
        self.assertTrue(out.at[0, "ver_irv"])
        self.assertTrue(out.at[0, "ver_irv_basis"].startswith("Assumed"))

    def test_no_context_file(self):
        out = run([finding()], asset_context=None, default_impact=3)
        self.assertEqual(out.at[0, "ver_pain"], 3)

    def test_impact_out_of_range_is_rejected(self):
        with self.assertRaises(ValueError):
            load_asset_context(b"host,impact\n10.0.0.1,9\n")


class ImpactRating(unittest.TestCase):
    def test_severity_caps_the_asset_ceiling(self):
        out = run([
            finding(severity="Critical", cvss=9.8),
            finding(severity="High", cvss=7.5),
            finding(severity="Medium", cvss=5.0),
            finding(severity="Low", cvss=2.0),
            finding(severity="Low", cvss=0.0),
        ])
        self.assertEqual(out["ver_pain"].tolist(), [5, 4, 3, 2, 1])


class Timeframes(unittest.TestCase):
    def test_table_lookup_for_each_class(self):
        for cert_class, table in PVR_DAYS.items():
            lev_irv = run([finding(kev_listed=True)], cert_class)
            lev_nirv = run([finding(kev_listed=True, host="192.0.2.1")], cert_class,
                           default_impact=5)
            nlev = run([finding()], cert_class)
            self.assertEqual(lev_irv.at[0, "ver_due_days"], table[5][0])
            self.assertEqual(lev_nirv.at[0, "ver_due_days"], table[5][1])
            self.assertEqual(nlev.at[0, "ver_due_days"], table[5][2])

    def test_n1_has_no_deadline_and_never_expires(self):
        out = run([finding(severity="Low", cvss=0.0, age_days=900)])
        self.assertTrue(pd.isna(out.at[0, "ver_due_days"]))
        self.assertTrue(pd.isna(out.at[0, "days_left"]))
        self.assertFalse(out.at[0, "expired"])

    def test_legacy_columns_are_overwritten(self):
        out = run([finding(kev_listed=True, age_days=10)], "C")
        self.assertEqual(out.at[0, "remediation_days"], 2)
        self.assertEqual(out.at[0, "days_left"], -8)
        self.assertTrue(out.at[0, "expired"])

    def test_accepted_after_192_days(self):
        out = run([finding(age_days=ACCEPT_AFTER_DAYS), finding(age_days=ACCEPT_AFTER_DAYS + 1)])
        self.assertEqual(out["ver_accept_required"].tolist(), [False, True])


class ReportableIncident(unittest.TestCase):
    def test_internet_reachable_rule(self):
        row = finding(kev_listed=True, host="203.0.113.10")      # LEV, IRV, N4
        self.assertEqual(run([row], "B").at[0, "ver_incident"], "may")
        self.assertEqual(run([row], "C").at[0, "ver_incident"], "should")

    def test_internal_rule_needs_n5(self):
        row = finding(kev_listed=True, host="192.0.2.1")         # LEV, not IRV
        self.assertEqual(run([row], "D", default_impact=5).at[0, "ver_incident"], "should")
        self.assertEqual(run([row], "C", default_impact=5).at[0, "ver_incident"], "may")
        self.assertEqual(run([row], "D", default_impact=4).at[0, "ver_incident"], "")

    def test_not_likely_exploitable_is_never_an_incident(self):
        self.assertEqual(run([finding()], "D").at[0, "ver_incident"], "")


class Integration(unittest.TestCase):
    def test_other_profiles_are_untouched(self):
        df = pd.DataFrame([finding()])
        out, summary = apply_profile(df, "FedRAMP Moderate/High")
        self.assertIsNone(summary)
        self.assertIs(out, df)

    def test_summary_and_detail_report(self):
        df = pd.DataFrame([
            finding(kev_listed=True, first_discovered=pd.Timestamp("2026-09-01")),
            finding(host="10.20.3.7", plugin_id="2", age_days=300,
                    first_discovered=pd.Timestamp("2025-12-01")),
        ])
        out, summary = apply_profile(df, "FedRAMP 2026 Class C", {"asset_context": CONTEXT})
        self.assertEqual(summary["class"], "C")
        self.assertEqual(summary["likely_exploitable"], 1)
        self.assertEqual(summary["accept_required"], 1)
        self.assertEqual(summary["pain"]["N5"], 1)

        records = detail_report(out)
        self.assertEqual(records[0]["potential_agency_impact"], "N5")
        self.assertEqual(records[0]["tracking_id"], "10.20.1.15:1")
        self.assertTrue(records[1]["accepted_vulnerability_required"])


if __name__ == "__main__":
    unittest.main()
