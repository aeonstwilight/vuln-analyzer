"""
report_generator.py
-------------------
Generates a professional vulnerability assessment PDF report.
Used as a module within the VulnAnalyzer Streamlit app.

Usage:
    from report_generator import generate_pdf_report
    pdf_bytes = generate_pdf_report(df, metrics, score, rating, profile_name, vendor, scan_filename)
"""

import io
import math
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import pandas as pd

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Image, KeepTogether
)
from reportlab.platypus.flowables import Flowable

# -----------------------------------------------------------------------
# Brand palette
# -----------------------------------------------------------------------
C_DARK       = colors.HexColor("#1a1a2e")   # header bg
C_ACCENT     = colors.HexColor("#378ADD")   # blue accent
C_CRITICAL   = colors.HexColor("#E24B4A")
C_HIGH       = colors.HexColor("#EF9F27")
C_MEDIUM     = colors.HexColor("#378ADD")
C_LOW        = colors.HexColor("#639922")
C_LIGHT_GRAY = colors.HexColor("#F5F5F5")
C_MID_GRAY   = colors.HexColor("#CCCCCC")
C_TEXT       = colors.HexColor("#1a1a2e")
C_MUTED      = colors.HexColor("#666666")
C_WHITE      = colors.white

SEV_COLORS = {
    "Critical": C_CRITICAL,
    "High":     C_HIGH,
    "Medium":   C_MEDIUM,
    "Low":      C_LOW,
}

RATING_COLORS = {
    "Low":      C_LOW,
    "Moderate": C_MEDIUM,
    "High":     C_HIGH,
    "Severe":   C_CRITICAL,
}

PAGE_W, PAGE_H = letter
MARGIN = 0.65 * inch

# -----------------------------------------------------------------------
# Custom flowables
# -----------------------------------------------------------------------
class ColorRect(Flowable):
    """A solid-color rectangle — used for section headers."""
    def __init__(self, width, height, fill_color, radius=4):
        super().__init__()
        self.width = width
        self.height = height
        self.fill_color = fill_color
        self.radius = radius

    def draw(self):
        self.canv.setFillColor(self.fill_color)
        self.canv.roundRect(0, 0, self.width, self.height, self.radius, fill=1, stroke=0)


class SectionHeader(Flowable):
    """Dark pill with white section title."""
    def __init__(self, text, width, bg=C_DARK):
        super().__init__()
        self.text = text
        self.width = width
        self.height = 26
        self.bg = bg

    def draw(self):
        c = self.canv
        c.setFillColor(self.bg)
        c.roundRect(0, 0, self.width, self.height, 4, fill=1, stroke=0)
        c.setFillColor(C_WHITE)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(10, 8, self.text.upper())


class MetricBox(Flowable):
    """Single metric card: colored top bar + large number + label."""
    def __init__(self, label, value, sub, bar_color, width=110, height=72):
        super().__init__()
        self.label = label
        self.value = str(value)
        self.sub = sub
        self.bar_color = bar_color
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        c.setFillColor(C_LIGHT_GRAY)
        c.roundRect(0, 0, self.width, self.height, 4, fill=1, stroke=0)
        c.setFillColor(self.bar_color)
        c.roundRect(0, self.height - 6, self.width, 6, 2, fill=1, stroke=0)
        c.setFillColor(C_TEXT)
        c.setFont("Helvetica-Bold", 22)
        c.drawCentredString(self.width / 2, self.height - 38, self.value)
        c.setFillColor(C_MUTED)
        c.setFont("Helvetica", 8)
        c.drawCentredString(self.width / 2, self.height - 50, self.label.upper())
        c.setFont("Helvetica", 7)
        c.drawCentredString(self.width / 2, 8, self.sub)


class RiskGauge(Flowable):
    """Horizontal progress bar showing risk score and rating."""
    def __init__(self, score, rating, width=300, height=28):
        super().__init__()
        self.score = score
        self.rating = rating
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        bar_h = 10
        pct = min(self.score / 500, 1.0)
        fill_color = RATING_COLORS.get(self.rating, C_MEDIUM)

        c.setFillColor(C_LIGHT_GRAY)
        c.roundRect(0, self.height - bar_h - 4, self.width, bar_h, 4, fill=1, stroke=0)
        if pct > 0:
            c.setFillColor(fill_color)
            c.roundRect(0, self.height - bar_h - 4, self.width * pct, bar_h, 4, fill=1, stroke=0)

        c.setFillColor(fill_color)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(0, self.height - bar_h - 20, f"Risk score: {self.score}  |  Rating: {self.rating}")


# -----------------------------------------------------------------------
# Chart helpers (matplotlib → PNG bytes → ReportLab Image)
# -----------------------------------------------------------------------
def _fig_to_image(fig, width_inch, height_inch):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                facecolor="none", transparent=True)
    plt.close(fig)
    buf.seek(0)
    return Image(buf, width=width_inch * inch, height=height_inch * inch)


def _chart_severity_donut(df):
    sev_counts = df["severity"].value_counts()
    labels = [s for s in ["Critical", "High", "Medium", "Low"] if s in sev_counts]
    sizes  = [sev_counts[s] for s in labels]
    clrs   = ["#E24B4A", "#EF9F27", "#378ADD", "#639922"][:len(labels)]

    fig, ax = plt.subplots(figsize=(3.2, 2.6))
    wedges, _ = ax.pie(sizes, colors=clrs, startangle=90,
                       wedgeprops=dict(width=0.55, edgecolor="white", linewidth=1.5))
    total = sum(sizes)
    ax.text(0, 0, str(total), ha="center", va="center",
            fontsize=16, fontweight="bold", color="#1a1a2e")
    ax.text(0, -0.25, "total", ha="center", va="center",
            fontsize=7, color="#666666")
    legend = ax.legend(wedges, [f"{l} ({s})" for l, s in zip(labels, sizes)],
                       loc="lower center", bbox_to_anchor=(0.5, -0.22),
                       ncol=2, fontsize=7, frameon=False)
    ax.set_title("Severity distribution", fontsize=8, color="#666666", pad=6)
    fig.tight_layout()
    return _fig_to_image(fig, 3.0, 2.6)


def _chart_top_hosts(df, n=8):
    top = df["host"].value_counts().head(n)
    fig, ax = plt.subplots(figsize=(3.5, 2.6))
    bars = ax.barh(top.index[::-1], top.values[::-1], color="#378ADD", height=0.55)
    ax.set_xlabel("Vulnerabilities", fontsize=7, color="#666666")
    ax.tick_params(axis="both", labelsize=7, colors="#444444")
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.xaxis.grid(True, linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)
    for bar in bars:
        w = bar.get_width()
        ax.text(w + 0.2, bar.get_y() + bar.get_height() / 2,
                str(int(w)), va="center", fontsize=6, color="#444444")
    ax.set_title("Top hosts by vuln count", fontsize=8, color="#666666", pad=6)
    fig.tight_layout()
    return _fig_to_image(fig, 3.3, 2.6)


def _chart_aging_buckets(df):
    bins   = [0, 30, 60, 90, 180, 365, 10000]
    labels = ["0-30d", "31-60d", "61-90d", "91-180d", "181-365d", "365d+"]
    df = df.copy()
    df["Bucket"] = pd.cut(df["age_days"], bins=bins, labels=labels)
    counts = df["Bucket"].value_counts().reindex(labels, fill_value=0)

    fig, ax = plt.subplots(figsize=(5.5, 2.2))
    bar_colors = ["#639922", "#639922", "#EF9F27", "#EF9F27", "#E24B4A", "#E24B4A"]
    bars = ax.bar(labels, counts.values, color=bar_colors, width=0.6)
    ax.set_ylabel("Count", fontsize=7, color="#666666")
    ax.tick_params(axis="both", labelsize=7, colors="#444444")
    ax.spines[["top", "right"]].set_visible(False)
    ax.yaxis.grid(True, linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)
    for bar in bars:
        h = bar.get_height()
        if h > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.3,
                    str(int(h)), ha="center", fontsize=6, color="#444444")
    ax.set_title("Vulnerability aging buckets", fontsize=8, color="#666666", pad=6)
    fig.tight_layout()
    return _fig_to_image(fig, 5.2, 2.0)


def _chart_sla_compliance(df):
    sla_data = {}
    for sev in ["Critical", "High", "Medium", "Low"]:
        sub = df[df["severity"] == sev]
        total = len(sub)
        expired = len(sub[sub["expired"] == True])
        sla_data[sev] = (total, expired)

    sevs   = [s for s in ["Critical", "High", "Medium", "Low"] if sla_data[s][0] > 0]
    totals = [sla_data[s][0] for s in sevs]
    expired_counts = [sla_data[s][1] for s in sevs]
    compliant = [t - e for t, e in zip(totals, expired_counts)]

    fig, ax = plt.subplots(figsize=(5.5, 2.0))
    x = range(len(sevs))
    b1 = ax.bar(x, compliant, color=["#E24B4A", "#EF9F27", "#378ADD", "#639922"][:len(sevs)],
                width=0.5, label="Within SLA")
    b2 = ax.bar(x, expired_counts, bottom=compliant,
                color="#cccccc", width=0.5, label="Expired", alpha=0.7)
    ax.set_xticks(list(x))
    ax.set_xticklabels(sevs, fontsize=8)
    ax.set_ylabel("Count", fontsize=7, color="#666666")
    ax.tick_params(axis="y", labelsize=7, colors="#444444")
    ax.spines[["top", "right"]].set_visible(False)
    ax.yaxis.grid(True, linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)
    ax.legend(fontsize=7, frameon=False)
    ax.set_title("SLA compliance by severity", fontsize=8, color="#666666", pad=6)
    fig.tight_layout()
    return _fig_to_image(fig, 5.2, 2.0)


# -----------------------------------------------------------------------
# Table helpers
# -----------------------------------------------------------------------
def _sev_color(sev):
    return {
        "Critical": colors.HexColor("#FCEBEB"),
        "High":     colors.HexColor("#FAEEDA"),
        "Medium":   colors.HexColor("#E6F1FB"),
        "Low":      colors.HexColor("#EAF3DE"),
    }.get(sev, C_LIGHT_GRAY)


def _sev_text_color(sev):
    return {
        "Critical": colors.HexColor("#791F1F"),
        "High":     colors.HexColor("#633806"),
        "Medium":   colors.HexColor("#0C447C"),
        "Low":      colors.HexColor("#27500A"),
    }.get(sev, C_TEXT)


def _build_vuln_table(df_subset, col_widths, show_cols, col_headers):
    styles = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=styles["Normal"],
                           fontSize=7, leading=9, textColor=C_TEXT)
    small_muted = ParagraphStyle("small_muted", parent=small, textColor=C_MUTED)

    header_row = [Paragraph(f"<b>{h}</b>", ParagraphStyle(
        "hdr", parent=small, textColor=C_WHITE, fontSize=7
    )) for h in col_headers]

    rows = [header_row]
    for _, row in df_subset.iterrows():
        sev = str(row.get("severity", ""))
        cells = []
        for col in show_cols:
            val = row.get(col, "")
            if col == "severity":
                p = Paragraph(f"<b>{val}</b>", ParagraphStyle(
                    "sev", parent=small,
                    textColor=_sev_text_color(sev),
                    backColor=_sev_color(sev),
                ))
            elif col == "expired":
                txt = "YES" if val else "no"
                clr = colors.HexColor("#791F1F") if val else C_MUTED
                p = Paragraph(txt, ParagraphStyle("exp", parent=small, textColor=clr))
            elif col == "days_left":
                txt = str(int(val)) if pd.notna(val) else "-"
                clr = colors.HexColor("#791F1F") if (pd.notna(val) and val < 0) else C_TEXT
                p = Paragraph(txt, ParagraphStyle("dl", parent=small, textColor=clr))
            elif col == "cvss":
                p = Paragraph(f"{float(val):.1f}" if pd.notna(val) else "-", small)
            else:
                p = Paragraph(str(val)[:80] if pd.notna(val) else "-", small)
            cells.append(p)
        rows.append(cells)

    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    row_count = len(rows)
    tbl_style = TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), C_DARK),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_LIGHT_GRAY]),
        ("GRID",         (0, 0), (-1, -1), 0.25, C_MID_GRAY),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ("LEFTPADDING",  (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW",    (0, 0), (-1, 0), 1, C_ACCENT),
    ])
    tbl.setStyle(tbl_style)
    return tbl


# -----------------------------------------------------------------------
# Header / footer callbacks
# -----------------------------------------------------------------------
def _make_page_template(title, generated_at):
    def on_page(canvas, doc):
        w, h = letter
        # Header bar
        canvas.setFillColor(C_DARK)
        canvas.rect(0, h - 0.55 * inch, w, 0.55 * inch, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 11)
        canvas.drawString(MARGIN, h - 0.35 * inch, title)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#99BBDD"))
        canvas.drawRightString(w - MARGIN, h - 0.35 * inch, "CONFIDENTIAL")

        # Footer
        canvas.setFillColor(C_MID_GRAY)
        canvas.rect(0, 0, w, 0.4 * inch, fill=1, stroke=0)
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(MARGIN, 0.15 * inch, f"Generated: {generated_at}")
        canvas.drawCentredString(w / 2, 0.15 * inch, "VulnAnalyzer — Confidential")
        canvas.drawRightString(w - MARGIN, 0.15 * inch, f"Page {doc.page}")

    return on_page


# -----------------------------------------------------------------------
# Style helpers
# -----------------------------------------------------------------------
def _styles():
    base = getSampleStyleSheet()
    s = {}
    s["title"] = ParagraphStyle("rptTitle",
        fontName="Helvetica-Bold", fontSize=28, textColor=C_WHITE,
        spaceAfter=4, leading=32)
    s["subtitle"] = ParagraphStyle("rptSubtitle",
        fontName="Helvetica", fontSize=11, textColor=colors.HexColor("#99BBDD"),
        spaceAfter=2)
    s["meta"] = ParagraphStyle("rptMeta",
        fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#AAAACC"),
        spaceAfter=2)
    s["h2"] = ParagraphStyle("rptH2",
        fontName="Helvetica-Bold", fontSize=12, textColor=C_TEXT,
        spaceBefore=14, spaceAfter=6)
    s["body"] = ParagraphStyle("rptBody",
        fontName="Helvetica", fontSize=9, textColor=C_TEXT,
        leading=14, spaceAfter=4)
    s["body_muted"] = ParagraphStyle("rptBodyMuted",
        fontName="Helvetica", fontSize=8, textColor=C_MUTED,
        leading=12, spaceAfter=4)
    s["finding"] = ParagraphStyle("rptFinding",
        fontName="Helvetica", fontSize=8, textColor=C_TEXT,
        leading=12, leftIndent=10, spaceAfter=3)
    return s


# -----------------------------------------------------------------------
# Cover page
# -----------------------------------------------------------------------
def _build_cover(story, styles, metrics, score, rating,
                 profile_name, vendor, scan_filename, generated_at):
    usable_w = PAGE_W - 2 * MARGIN

    # Dark cover block drawn via a canvas callback — we simulate with a table
    cover_data = [[""]]
    cover_tbl = Table(cover_data, colWidths=[usable_w], rowHeights=[2.8 * inch])
    cover_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_DARK),
        ("ROUNDEDCORNERS", [6]),
    ]))

    # We'll float text over it using a nested approach
    cover_inner = [
        Paragraph("Vulnerability Assessment Report", styles["title"]),
        Paragraph(f"Profile: {profile_name}  |  Vendor: {vendor}", styles["subtitle"]),
        Paragraph(f"Source: {scan_filename}", styles["meta"]),
        Paragraph(f"Generated: {generated_at}", styles["meta"]),
    ]
    inner_tbl = Table([[p] for p in cover_inner],
                      colWidths=[usable_w - 0.6 * inch])
    inner_tbl.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("BACKGROUND",    (0, 0), (-1, -1), C_DARK),
    ]))

    outer = Table([[inner_tbl]], colWidths=[usable_w])
    outer.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_DARK),
        ("TOPPADDING",    (0, 0), (-1, -1), 24),
        ("LEFTPADDING",   (0, 0), (-1, -1), 20),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 20),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 24),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(outer)
    story.append(Spacer(1, 0.22 * inch))

    # Risk rating pill
    rating_color = RATING_COLORS.get(rating, C_MEDIUM)
    risk_data = [[
        Paragraph(f"<b>Risk rating: {rating}</b>", ParagraphStyle(
            "riskpill", fontName="Helvetica-Bold", fontSize=11,
            textColor=C_WHITE)),
        Paragraph(f"Score: {score}", ParagraphStyle(
            "riskscore", fontName="Helvetica", fontSize=9,
            textColor=colors.HexColor("#DDDDDD"))),
    ]]
    risk_tbl = Table(risk_data, colWidths=[2.5 * inch, 1.5 * inch])
    risk_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), rating_color),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(risk_tbl)
    story.append(Spacer(1, 0.18 * inch))

    # Metric boxes row
    box_w = (usable_w - 4 * 10) / 5
    boxes = [
        MetricBox("Critical", metrics["critical"], f"SLA: 30 days", C_CRITICAL, width=box_w),
        MetricBox("High",     metrics["high"],     f"SLA: 30 days", C_HIGH,     width=box_w),
        MetricBox("Medium",   metrics["medium"],   f"SLA: 90 days", C_MEDIUM,   width=box_w),
        MetricBox("Low",      metrics["low"],      f"SLA: 180 days",C_LOW,      width=box_w),
        MetricBox("Expired",  metrics["expired"],  f"SLA breached", C_CRITICAL, width=box_w),
    ]
    boxes_row = [[b for b in boxes]]
    boxes_tbl = Table(boxes_row, colWidths=[box_w] * 5,
                      rowHeights=[72], hAlign="LEFT")
    boxes_tbl.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("COLPADDING",    (0, 0), (-1, -1), 5),
    ]))
    story.append(boxes_tbl)
    story.append(Spacer(1, 0.25 * inch))

    # Executive summary text
    story.append(SectionHeader("Executive Summary", usable_w))
    story.append(Spacer(1, 8))

    expired_pct = round(metrics["expired"] / max(metrics["total"], 1) * 100)
    critical_high = metrics["critical"] + metrics["high"]

    summary = (
        f"This report presents the results of a vulnerability assessment conducted against "
        f"{metrics['total']} findings identified in the provided scan file. "
        f"The assessment was evaluated against the <b>{profile_name}</b> compliance profile. "
        f"<br/><br/>"
        f"A total of <b>{critical_high}</b> critical and high severity vulnerabilities were identified, "
        f"representing the highest remediation priority. "
        f"<b>{metrics['expired']}</b> vulnerabilities ({expired_pct}%) have exceeded their SLA "
        f"remediation deadline and require immediate attention. "
        f"The overall risk posture has been rated <b>{rating}</b> with a composite score of {score}."
    )
    story.append(Paragraph(summary, styles["body"]))


# -----------------------------------------------------------------------
# Key findings section
# -----------------------------------------------------------------------
def _build_findings(story, styles, df):
    usable_w = PAGE_W - 2 * MARGIN
    story.append(Spacer(1, 0.15 * inch))
    story.append(SectionHeader("Key Findings", usable_w))
    story.append(Spacer(1, 8))

    findings = []

    # Most expired
    expired_df = df[df["expired"] == True].sort_values("age_days", ascending=False)
    if not expired_df.empty:
        worst = expired_df.iloc[0]
        findings.append(
            f"<b>Oldest expired vulnerability:</b> {worst.get('plugin_name','')} "
            f"on host {worst.get('host','')} — {int(worst.get('age_days',0))} days old "
            f"({worst.get('severity','')} / CVSS {worst.get('cvss',0):.1f})"
        )

    # Hosts with most criticals
    crit_hosts = df[df["severity"] == "Critical"]["host"].value_counts().head(3)
    if not crit_hosts.empty:
        host_str = ", ".join([f"{h} ({c})" for h, c in crit_hosts.items()])
        findings.append(f"<b>Hosts with most critical vulns:</b> {host_str}")

    # CVSS 9+
    cvss9 = df[df["cvss"] >= 9.0]
    if not cvss9.empty:
        findings.append(
            f"<b>CVSS 9.0+ vulnerabilities:</b> {len(cvss9)} findings with maximum severity scores "
            f"across {cvss9['Host'].nunique()} hosts"
        )

    # Exploit available
    if "exploit_available" in df.columns:
        exploitable = df[df["exploit_available"].astype(str).str.lower().isin(["yes", "true", "1"])]
        if not exploitable.empty:
            findings.append(
                f"<b>Exploitable vulnerabilities:</b> {len(exploitable)} findings have known exploit code available"
            )

    if not findings:
        findings.append("No critical key findings identified. Review full table for details.")

    for f in findings:
        story.append(Paragraph(f"• {f}", styles["finding"]))

    story.append(Spacer(1, 6))


# -----------------------------------------------------------------------
# Charts section
# -----------------------------------------------------------------------
def _build_charts(story, styles, df):
    usable_w = PAGE_W - 2 * MARGIN
    story.append(PageBreak())
    story.append(SectionHeader("Visual Analysis", usable_w))
    story.append(Spacer(1, 10))

    # Row 1: donut + top hosts
    img_donut    = _chart_severity_donut(df)
    img_hosts    = _chart_top_hosts(df)
    charts_row1  = Table([[img_donut, img_hosts]],
                         colWidths=[3.1 * inch, 3.6 * inch])
    charts_row1.setStyle(TableStyle([
        ("VALIGN",  (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
    ]))
    story.append(charts_row1)
    story.append(Spacer(1, 6))

    # Row 2: aging + SLA compliance
    img_aging = _chart_aging_buckets(df)
    img_sla   = _chart_sla_compliance(df)
    charts_row2 = Table([[img_aging], [img_sla]],
                        colWidths=[usable_w])
    charts_row2.setStyle(TableStyle([
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
    ]))
    story.append(charts_row2)


# -----------------------------------------------------------------------
# Vulnerability tables section
# -----------------------------------------------------------------------
def _build_vuln_tables(story, styles, df):
    usable_w = PAGE_W - 2 * MARGIN

    for sev in ["Critical", "High", "Medium", "Low"]:
        sub = df[df["severity"] == sev].sort_values("age_days", ascending=False)
        if sub.empty:
            continue

        story.append(PageBreak())
        story.append(SectionHeader(
            f"{sev} Vulnerabilities ({len(sub)})",
            usable_w,
            bg=SEV_COLORS.get(sev, C_DARK)
        ))
        story.append(Spacer(1, 8))

        # Show top 50 per severity to keep PDF manageable
        show = sub.head(50)
        if len(sub) > 50:
            story.append(Paragraph(
                f"Showing top 50 of {len(sub)} {sev.lower()} vulnerabilities ordered by age.",
                styles["body_muted"]
            ))
            story.append(Spacer(1, 4))

        col_widths = [0.85*inch, 2.2*inch, 1.1*inch, 0.55*inch, 0.55*inch, 0.65*inch]
        show_cols  = ["plugin_id", "plugin_name", "host", "cvss", "age_days", "days_left"]
        headers    = ["Plugin ID", "Name", "Host", "CVSS", "Age (d)", "Days Left"]

        tbl = _build_vuln_table(show, col_widths, show_cols, headers)
        story.append(tbl)
        story.append(Spacer(1, 6))

        # Expired callout for this severity
        expired_sub = sub[sub["expired"] == True]
        if not expired_sub.empty:
            expired_note = (
                f"<b>{len(expired_sub)}</b> of {len(sub)} {sev.lower()} vulnerabilities "
                f"have exceeded their SLA remediation window."
            )
            note_style = ParagraphStyle("note",
                fontName="Helvetica", fontSize=8,
                textColor=colors.HexColor("#791F1F"),
                backColor=colors.HexColor("#FCEBEB"),
                leftIndent=8, rightIndent=8,
                borderPadding=(6, 8, 6, 8),
                leading=12)
            story.append(Paragraph(expired_note, note_style))


# -----------------------------------------------------------------------
# Remediation guidance section
# -----------------------------------------------------------------------
def _build_remediation(story, styles, df, profile):
    usable_w = PAGE_W - 2 * MARGIN
    story.append(PageBreak())
    story.append(SectionHeader("Remediation Priorities", usable_w))
    story.append(Spacer(1, 8))

    priorities = [
        ("Immediate (Critical & Expired High)", C_CRITICAL,
         df[(df["severity"] == "Critical") | ((df["severity"] == "High") & (df["expired"] == True))]),
        ("Short-term (High within SLA)",  C_HIGH,
         df[(df["severity"] == "High") & (df["expired"] == False)]),
        ("Medium-term (Medium)",          C_MEDIUM,
         df[df["severity"] == "Medium"]),
    ]

    for label, clr, subset in priorities:
        if subset.empty:
            continue
        row_data = [[
            Paragraph(f"<b>{label}</b>", ParagraphStyle(
                "plab", fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE)),
            Paragraph(f"{len(subset)} vulnerabilities", ParagraphStyle(
                "pcnt", fontName="Helvetica", fontSize=9, textColor=C_WHITE)),
        ]]
        tbl = Table(row_data, colWidths=[4.5 * inch, 1.8 * inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), clr),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (1, 0), (1, 0), "RIGHT"),
            ("RIGHTPADDING",  (1, 0), (1, 0), 12),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 4))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Remediation SLA reference (selected compliance profile):",
        styles["body"]
    ))
    sla_rows = [["Severity", "SLA Window", "Basis"]]
    sla_basis = {
        "Critical": "Immediate risk of exploitation",
        "High": "High likelihood of exploitation",
        "Medium": "Potential attack vector",
        "Low": "Defense in depth",
    }
    for sev, days in profile.items():
        sla_rows.append([sev, f"{days} days", sla_basis.get(sev, "")])

    sla_tbl = Table(sla_rows, colWidths=[1.5*inch, 1.2*inch, 4.0*inch])
    sla_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_LIGHT_GRAY]),
        ("GRID",          (0, 0), (-1, -1), 0.25, C_MID_GRAY),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    story.append(sla_tbl)


# -----------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------
def generate_pdf_report(df, metrics, score, rating, profile_name, vendor,
                        scan_filename="scan.csv", profile=None):
    """
    Generate a PDF vulnerability report and return the bytes.

    Parameters
    ----------
    df            : enriched DataFrame from clean_and_enrich()
    metrics       : dict from generate_metrics()
    score         : int from calculate_risk()
    rating        : str from calculate_risk()
    profile_name  : str  e.g. "FedRAMP Moderate/High"
    vendor        : str  e.g. "Nessus"
    scan_filename : str  original filename shown on cover
    profile       : dict SLA profile {severity: days}

    Returns
    -------
    bytes  — PDF binary, ready for st.download_button()
    """
    if profile is None:
        profile = {"Critical": 30, "High": 30, "Medium": 90, "Low": 180}

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    report_title = "Vulnerability Assessment Report"

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=0.75 * inch,
        bottomMargin=0.55 * inch,
        title=report_title,
        author="VulnAnalyzer",
        subject=f"{profile_name} Assessment",
    )

    s = _styles()
    story = []
    on_page = _make_page_template(report_title, generated_at)

    _build_cover(story, s, metrics, score, rating,
                 profile_name, vendor, scan_filename, generated_at)
    _build_findings(story, s, df)
    _build_charts(story, s, df)
    _build_vuln_tables(story, s, df)
    _build_remediation(story, s, df, profile)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    buf.seek(0)
    return buf.read()
