#!/usr/bin/env python3
# report/generate_report.py

import argparse
from datetime import datetime
from pathlib import Path
import pandas as pd

# ---- ReportLab imports ----
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage, PageBreak

# ---- Headless charts (Linux-friendly) ----
import matplotlib
matplotlib.use("Agg")  # headless-friendly backend
import matplotlib.pyplot as plt

# Shared analysis helpers (centralised in wifi_analysis.py)
from report.wifi_analysis import mac_summary_enhanced, per_frame_view

# Optional DB imports (CSV-only environments still work)
try:
    from report.db_adapter import (
        connect_db,
        fetch_project_metadata,
        fetch_ingest_as_analysis_df,
        latest_project_id,
    )
except Exception:
    connect_db = None
    fetch_project_metadata = None
    fetch_ingest_as_analysis_df = None
    latest_project_id = None

# Analysis helpers (sections render only if needed columns exist)
try:
    from report.wifi_analysis import (
        compute_time_window,
        frame_size_stats,
        interarrival_stats,
        beacon_summary,
        infer_aps,
        talkers,
        mac_pairs,
        rts_cts_stats,
        ap_client_links,
    )
    HAVE_ANALYSIS = True
except Exception:
    HAVE_ANALYSIS = False


# -----------------------
# Loaders & Summaries
# -----------------------
def load_scan_csv(csv_path: Path) -> pd.DataFrame:
    """Load original scan CSV (timestamp, ssid, bssid, channel, rssi)."""
    df = pd.read_csv(csv_path)
    expected = ["timestamp", "ssid", "bssid", "channel", "rssi"]
    missing = [c for c in expected if c not in df.columns]
    if missing:
        raise SystemExit(f"CSV is missing columns: {missing}")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["ssid"] = df["ssid"].fillna("").astype(str)
    df["bssid"] = df["bssid"].fillna("").astype(str)
    df["channel"] = df["channel"].astype(str)
    df["rssi"] = pd.to_numeric(df["rssi"], errors="coerce")
    return df


def summarize_bssid_table(df: pd.DataFrame) -> pd.DataFrame:
    """CSV-mode: aggregate per BSSID (MAC)."""
    if df.empty:
        return pd.DataFrame(columns=[
            "bssid","frames","first_seen","last_seen","min_rssi","avg_rssi","max_rssi","ssids","channels"
        ])
    g = df.groupby("bssid", dropna=False)
    out = g.agg(
        frames=("bssid", "size"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        min_rssi=("rssi", "min"),
        avg_rssi=("rssi", "mean"),
        max_rssi=("rssi", "max"),
    ).reset_index()
    ssids = g["ssid"].agg(lambda s: ", ".join(sorted({x for x in s if x})))
    chans = g["channel"].agg(lambda s: ", ".join(sorted({str(x) for x in s if str(x)})))
    out["ssids"] = ssids.values
    out["channels"] = chans.values
    out = out.sort_values(["frames", "bssid"], ascending=[False, True])
    return out


# -----------------------
# Small helpers
# -----------------------
def _first_present(df: pd.DataFrame, candidates: list[str]) -> str | None:
    """Return the first column name that exists in df (case-sensitive)."""
    for c in candidates:
        if c in df.columns:
            return c
    return None


def _fmt_ts(ts):
    if pd.isna(ts):
        return ""
    if not isinstance(ts, pd.Timestamp):
        ts = pd.to_datetime(ts, errors="coerce")
    if pd.isna(ts):
        return ""
    return ts.strftime("%Y-%m-%d %H:%M:%S")


# --- dBm color helpers (green = strong, amber = fair, red = weak) ---
def _to_float(x):
    try:
        return float(str(x))
    except Exception:
        return None

def _dbm_color(v):
    if v is None:
        return None
    # thresholds: adjust if you like
    if v >= -60:            # strong signal (closer to 0)
        return colors.HexColor("#10B981")  # green
    if v >= -75:            # fair
        return colors.HexColor("#F59E0B")  # amber
    return colors.HexColor("#EF4444")      # red (weak)


# -----------------------
# Charts
# -----------------------
PALETTE = ["#0072B2","#E69F00","#009E73","#D55E00","#CC79A7","#56B4E9","#F0E442","#6A737B"]
MIN_FRAMES_FOR_CHART = 5  # filter tiny n for RSSI chart

plt.rcParams.update({
    "figure.dpi": 140, "savefig.dpi": 140,
    "font.size": 10, "axes.titlesize": 11, "axes.labelsize": 10,
    "axes.grid": True, "grid.alpha": 0.25, "figure.autolayout": True
})

def _chart_frames_over_time(df: pd.DataFrame, outdir: Path, ts_col: str) -> str | None:
    ts = pd.to_datetime(df[ts_col], errors="coerce")
    if ts.dropna().empty:
        return None
    per_min = ts.dt.floor("min").value_counts().sort_index()
    if per_min.empty or len(per_min) < 2:
        return None  # need at least two time buckets to show a meaningful trend
    fig, ax = plt.subplots(figsize=(7,3))
    ax.plot(per_min.index, per_min.values, linewidth=1.6)
    ax.set_xlabel("Time"); ax.set_ylabel("Frames/min")
    ax.set_title("Traffic volume over time")
    path = outdir / "frames_over_time.png"
    plt.tight_layout(); plt.savefig(path); plt.close()
    return str(path)

def _chart_rssi_by_ssid(summary_df: pd.DataFrame, outdir: Path) -> str | None:
    # expects columns: ssid/SSID, min_rssi, avg_rssi, max_rssi, frames
    name_col = "ssid" if "ssid" in summary_df.columns else ("SSID" if "SSID" in summary_df.columns else None)
    if not name_col or summary_df.empty:
        return None
    df = summary_df[[name_col,"min_rssi","avg_rssi","max_rssi","frames"]].dropna(subset=["avg_rssi"]).copy()
    if df.empty:
        return None
    df = df[df["frames"] >= MIN_FRAMES_FOR_CHART].sort_values("avg_rssi")  # weaker→stronger
    if df.empty:
        return None
    fig_h = max(3, 0.28*len(df))
    fig, ax = plt.subplots(figsize=(7, fig_h))
    y = range(len(df))
    ax.barh(list(y), df["avg_rssi"], color=PALETTE[0], label="Avg")
    for i, (mn, mx) in enumerate(zip(df["min_rssi"], df["max_rssi"])):
        ax.text(mn, i, f"min {mn:.0f}", va="center", ha="right", fontsize=8)
        ax.text(mx, i, f"max {mx:.0f}", va="center", ha="left", fontsize=8)
    ax.set_yticks(list(y))
    ax.set_yticklabels(df[name_col])
    ax.set_xlabel("Signal (dBm, higher/less negative = stronger)")
    ax.set_title("Signal quality by SSID (min/avg/max)")
    path = outdir / "rssi_by_ssid.png"
    plt.tight_layout(); plt.savefig(path); plt.close()
    return str(path)

def _chart_enc_auth(df: pd.DataFrame, outdir: Path) -> str | None:
    if not set(["encType","authMode"]).issubset(df.columns):
        return None
    pv = df.groupby(["encType","authMode"]).size().reset_index(name="n")
    if pv.empty:
        return None
    pivot = pv.pivot(index="encType", columns="authMode", values="n").fillna(0)
    fig, ax = plt.subplots(figsize=(7, 3 + 0.3*len(pivot)))
    bottom = None
    for i, col in enumerate(pivot.columns):
        vals = pivot[col]
        ax.bar(pivot.index, vals, bottom=bottom, label=str(col), color=PALETTE[1+(i % (len(PALETTE)-1))])
        bottom = vals if bottom is None else bottom + vals
    ax.set_ylabel("Count"); ax.set_title("Encryption × Auth distribution")
    ax.legend(title="authMode", fontsize=8)
    path = outdir / "enc_auth_stack.png"
    plt.tight_layout(); plt.savefig(path); plt.close()
    return str(path)

def make_charts(source: str, df: pd.DataFrame, outdir: Path) -> list[str]:
    """
    Returns list of PNG paths. Source is 'csv' or 'db'.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    charts = []

    # Frames-over-time for both modes
    ts_col = "timestamp_ms" if "timestamp_ms" in df.columns else ("timestamp" if "timestamp" in df.columns else None)
    if ts_col:
        p = _chart_frames_over_time(df, outdir, ts_col)
        if p: charts.append(p)

    if source == "csv":
        # Build a small summary for RSSI by SSID
        if set(["ssid","rssi"]).issubset(df.columns):
            tmp = df.copy()
            g = tmp.groupby("ssid", dropna=False).agg(
                frames=("ssid","size"),
                min_rssi=("rssi","min"),
                avg_rssi=("rssi","mean"),
                max_rssi=("rssi","max")
            ).reset_index()
            g = g.rename(columns={"ssid":"ssid"})
            p = _chart_rssi_by_ssid(g, outdir)
            if p: charts.append(p)
    else:
        # DB/analysis: leverage mac_summary_enhanced for SSID + RSSI stats if present
        try:
            summ = mac_summary_enhanced(df)
            if not summ.empty and "ssid" in summ.columns:
                p = _chart_rssi_by_ssid(summ, outdir)
                if p: charts.append(p)
        except Exception:
            pass
        # encType × authMode
        p = _chart_enc_auth(df, outdir)
        if p: charts.append(p)

    return charts


# -----------------------
# Branding helpers
# -----------------------
def _resolve_logo_path(user_arg: str | None, script_dir: Path, repo_root: Path) -> str | None:
    """Resolve a logo path from user arg or common locations."""
    def _ok(p: Path) -> Path | None:
        try:
            return p if p.exists() else None
        except Exception:
            return None

    if user_arg:
        p = Path(user_arg)
        checks = [p] if p.is_absolute() else [
            Path.cwd() / p,
            repo_root / p,
            script_dir / p,
        ]
        for c in checks:
            c = c.resolve()
            if _ok(c):
                return str(c)

    # Auto-detect
    for base in (Path.cwd(), repo_root, script_dir):
        for rel in ("assets/y404_logo.png", "y404_logo.png"):
            c = (base / rel).resolve()
            if _ok(c):
                return str(c)
    return None


def _make_logo(logo_path: str, align: str, max_w_mm: float, max_h_mm: float, upscale: bool) -> RLImage | Paragraph:
    try:
        img = RLImage(str(logo_path))
        iw, ih = float(img.imageWidth), float(img.imageHeight)
        max_w_pt, max_h_pt = max_w_mm * mm, max_h_mm * mm
        scale = min(max_w_pt / iw, max_h_pt / ih)
        if not upscale:
            scale = min(scale, 1.0)
        img.drawWidth = iw * scale
        img.drawHeight = ih * scale
        img.hAlign = {"left": "LEFT", "center": "CENTER", "right": "RIGHT"}.get(align, "RIGHT")
        return img
    except Exception as e:
        return Paragraph(f"(logo failed to load: {e})", getSampleStyleSheet()["Normal"])


# -----------------------
# PDF builder
# -----------------------
def build_pdf(df: pd.DataFrame, out_pdf: Path, meta: dict, source: str):
    """
    Build the PDF. df may be:
      - CSV schema (timestamp, ssid, bssid, channel, rssi)
      - DB/analysis schema (timestamp_ms, frame_len, src_mac/dst_mac, SSID/encType/authMode/contentLength, strength/rssi, ...)
    """
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Tiny", fontSize=8, leading=10))

    # --- subtle professional theme colors ---
    HEADER_BG = colors.HexColor("#F3F4F6")
    GRID = colors.HexColor("#D1D5DB")
    STRIPE = [colors.white, colors.HexColor("#FAFAFA")]
    HEADER_TXT = colors.HexColor("#111827")

    doc = SimpleDocTemplate(
        str(out_pdf),
        pagesize=meta.get("pagesize", A4),
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=25 * mm,
        bottomMargin=18 * mm,
    )

    story = []

    # ---- logo ----
    logo_path = meta.get("logo_path")
    if logo_path:
        logo = _make_logo(
            logo_path=logo_path,
            align=str(meta.get("logo_align", "right")).lower(),
            max_w_mm=float(meta.get("logo_max_width_mm", 60.0)),
            max_h_mm=float(meta.get("logo_max_height_mm", 22.0)),
            upscale=bool(meta.get("logo_upscale", False)),
        )
        story += [logo, Spacer(1, 6)]

    # ---- Title block ----
    title = meta.get("title", "Wireless Intelligence Report")
    project = meta.get("project", "Team 404 – Prototype")
    subtitle = meta.get("subtitle", "Prototype report")
    when = datetime.now().strftime("%Y-%m-%d %H:%M")
    story += [
        Paragraph(f"<b>{title}</b>", styles["Title"]),
        Spacer(1, 6),
        Paragraph(f"{project}<br/>Generated: {when}", styles["Normal"]),
        Spacer(1, 8),
        Paragraph(
            "This report summarises 802.11 frame activity observed during the capture window. "
            "Key metrics, basic traffic characteristics, and observed MAC activity are shown below. "
            "Intended use: quick situational awareness for troubleshooting, site surveys, and security triage.",
            styles["Normal"]
        ),
        Spacer(1, 12),
    ]

    # ---- Schema detection ----
    has_csv_schema = all(c in df.columns for c in ["timestamp", "ssid", "bssid", "channel", "rssi"])
    has_ts_ms = "timestamp_ms" in df.columns

    total_frames = int(df.shape[0])
    summary_bits = [f"{total_frames} frames observed"]
    if has_csv_schema:
        summary_bits.insert(0, f"{df['bssid'].nunique()} unique MACs across {df['ssid'].replace('', pd.NA).dropna().nunique()} SSIDs")
    else:
        mac_col = _first_present(df, ["src_mac", "srcMac", "dst_mac", "dstMac", "bssid"])
        if mac_col:
            summary_bits.insert(0, f"{df[mac_col].nunique()} unique MACs")

    story += [Paragraph("<b>Summary</b>: " + " • ".join(summary_bits) + ".", styles["Normal"]), Spacer(1, 12)]

    # ---- Parameters ----
    if has_csv_schema:
        min_ts = _fmt_ts(df["timestamp"].min())
        max_ts = _fmt_ts(df["timestamp"].max())
    elif has_ts_ms:
        ts = pd.to_datetime(df["timestamp_ms"], unit="ms", errors="coerce")
        min_ts = _fmt_ts(ts.min())
        max_ts = _fmt_ts(ts.max())
    else:
        tcol = _first_present(df, ["time", "timestamp"])
        if tcol:
            ts = pd.to_datetime(df[tcol], errors="coerce")
            min_ts = _fmt_ts(ts.min())
            max_ts = _fmt_ts(ts.max())
        else:
            min_ts = max_ts = ""

    params_rows = [
        ["Records", f"{total_frames}"],
        ["Time range", f"{min_ts} → {max_ts}"],
        ["Capture Mode", meta.get("capture_mode", "(n/a)")],
        ["App version", meta.get("app_version", "0.1.0")],
    ]
    if has_csv_schema:
        params_rows.insert(0, ["Data file", meta.get("data_file_name", "(n/a)")])
        params_rows.append(["Filter SSID", meta.get("filter_ssid", "(none)")])

    project_meta = meta.get("project_meta") or {}
    if project_meta:
        params_rows.extend([
            ["Project ID", str(project_meta.get("projectID", ""))],
            ["Capture Type", str(project_meta.get("type", ""))],
            ["Project Start", _fmt_ts(project_meta.get("startTime") or project_meta.get("start_ms"))],
            ["Project Stop", _fmt_ts(project_meta.get("stopTime") or project_meta.get("end_ms"))],
        ])

    params_tbl = Table(params_rows, colWidths=[34 * mm, None])
    params_tbl.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, GRID),
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story += [Paragraph("<b>Parameters</b>", styles["Heading3"]), Spacer(1, 4), params_tbl, Spacer(1, 12)]

    # ---- Key Visuals (charts) ----
    chart_paths = make_charts("csv" if has_csv_schema else "db", df, Path("artifacts"))
    if chart_paths:
        story += [Paragraph("<b>Key Visuals</b>", styles["Heading2"]), Spacer(1, 6)]
        for p in chart_paths:
            story += [RLImage(p, width=170*mm, height=95*mm), Spacer(1, 4)]
        cap = ParagraphStyle("Cap", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#555"))
        story += [Paragraph("Charts: Frames/min timeline; RSSI by SSID (min/avg/max); Encryption × Auth (if available).", cap), Spacer(1, 12)]
        story += [PageBreak()]
    else:
        story += [Paragraph("<b>Key Visuals</b>", styles["Heading2"]),
                  Spacer(1, 4),
                  Paragraph("No chartable data for this run (capture too short / sample too small).", styles["Normal"]),
                  Spacer(1, 10)]

    # ---- Analytics sections (only if needed cols exist) ----
    if HAVE_ANALYSIS:
        analysis_df = df.copy()
        if "timestamp_ms" not in analysis_df.columns and "timestamp" in analysis_df.columns:
            ts = pd.to_datetime(analysis_df["timestamp"], errors="coerce")
            analysis_df["timestamp_ms"] = (ts.astype("int64") // 1_000_000).astype("int64")

        if "frame_len" in analysis_df.columns:
            sz = frame_size_stats(analysis_df)
            story += [
                Paragraph("<b>Frame Size Distribution</b>", styles["Heading3"]),
                Spacer(1, 4),
                Paragraph(
                    f"Min {sz['min']} B • P50 {sz['p50']:.0f} B • P95 {sz['p95']:.0f} B • "
                    f"P99 {sz['p99']:.0f} B • Max {sz['max']} B • "
                    f"Frames {sz['count']} • Bytes {sz['bytes_total']}",
                    styles["Normal"]
                ),
                Spacer(1, 10),
            ]

        if "timestamp_ms" in analysis_df.columns:
            ia = interarrival_stats(analysis_df)
            story += [
                Paragraph("<b>Inter-Arrival Times</b>", styles["Heading3"]),
                Spacer(1, 4),
                Paragraph(
                    f"Mean {ia['mean_ms']:.2f} ms • Median {ia['p50_ms']:.2f} ms • P95 {ia['p95_ms']:.2f} ms",
                    styles["Normal"]
                ),
                Spacer(1, 10),
            ]

        if set(["frame_type", "subtype"]).issubset(analysis_df.columns):
            rtscts = rts_cts_stats(analysis_df)
            story += [
                Paragraph("<b>RTS / CTS</b>", styles["Heading3"]),
                Spacer(1, 4),
                Paragraph(
                    f"RTS: {rtscts['rts_count']} • CTS: {rtscts['cts_count']} • "
                    f"RTS→CTS match rate: {rtscts['match_rate']*100:.1f}%",
                    styles["Normal"]
                ),
                Spacer(1, 10),
            ]

        if set(["frame_type", "subtype", "bssid"]).issubset(analysis_df.columns):
            aps = infer_aps(analysis_df)
            links = ap_client_links(analysis_df, aps)
            if not links.empty:
                rows = [["SSID", "Channel", "AP (BSSID)", "Client MAC", "Frames"]]
                for r in links.head(10).itertuples(index=False):
                    rows.append([r.ssid or "<unknown>", r.channel if pd.notna(r.channel) else "-", r.ap_bssid, r.client_mac, int(r.frames)])
                tbl = Table(rows, repeatRows=1)
                tbl.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
                    ("GRID", (0, 0), (-1, -1), 0.25, GRID),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]))
                story += [Paragraph("<b>Access Points & SSIDs</b>", styles["Heading3"]), Spacer(1, 4), tbl, Spacer(1, 10)]

    # ---- Observed MACs (final table) ----
    if has_csv_schema:
        summary = summarize_bssid_table(df)
        header = ["#", "MAC (BSSID)", "SSID(s)", "Frames (n)", "First Seen", "Last Seen", "Min dBm", "Avg dBm", "Max dBm", "Ch"]
        rows = [header]
        for i, row in enumerate(summary.itertuples(index=False), start=1):
            rows.append([
                i,
                row.bssid or "(unknown)",
                (row.ssids or "")[:40],
                int(row.frames),
                _fmt_ts(row.first_seen),
                _fmt_ts(row.last_seen),
                f"{row.min_rssi:.0f}" if pd.notna(row.min_rssi) else "",
                f"{row.avg_rssi:.1f}" if pd.notna(row.avg_rssi) else "",
                f"{row.max_rssi:.0f}" if pd.notna(row.max_rssi) else "",
                row.channels,
            ])
        section_title = "Observed MAC Addresses (BSSID view)"
        table_col_align = {"frames_col": 3, "dbm_start": 6, "dbm_end": 8}
        col_widths = [8*mm, 32*mm, 40*mm, 22*mm, 32*mm, 32*mm, 16*mm, 16*mm, 16*mm, 16*mm]
    else:
        # Enhanced summary with your preferred order
        summary = mac_summary_enhanced(df)

        # stacked header labels for dBm (force bold)
        hdr_style = ParagraphStyle("Hdr", parent=styles["Normal"], fontSize=8, alignment=TA_CENTER, fontName="Helvetica-Bold")

        header = [
            "#", "MAC", "SSID(s)", "Frames (n)", "First Seen", "Last Seen",
            Paragraph("Min<br/>dBm", hdr_style),
            Paragraph("Avg<br/>dBm", hdr_style),
            Paragraph("Max<br/>dBm", hdr_style),
            "encType", "authMode",
        ]
        rows = [header]

        for i, row in enumerate(summary.itertuples(index=False), start=1):
            rows.append([
                i,
                getattr(row, "bssid", None) or getattr(row, "src_mac", None) or "(unknown)",
                str(getattr(row, "ssid", ""))[:40],
                int(getattr(row, "frames", 0) or 0),
                _fmt_ts(getattr(row, "first_seen", "")),
                _fmt_ts(getattr(row, "last_seen", "")),
                f"{getattr(row, 'min_rssi', float('nan')):.0f}" if pd.notna(getattr(row, "min_rssi", pd.NA)) else "",
                f"{getattr(row, 'avg_rssi', float('nan')):.1f}" if pd.notna(getattr(row, "avg_rssi", pd.NA)) else "",
                f"{getattr(row, 'max_rssi', float('nan')):.0f}" if pd.notna(getattr(row, "max_rssi", pd.NA)) else "",
                str(getattr(row, "encType", ""))[:12],
                str(getattr(row, "authMode", ""))[:12],
            ])
        section_title = "Observed MAC Addresses (enhanced)"
        table_col_align = {"frames_col": 3, "dbm_start": 6, "dbm_end": 8}
        col_widths = [8*mm, 32*mm, 40*mm, 22*mm, 32*mm, 32*mm, 16*mm, 16*mm, 16*mm, 18*mm, 18*mm]

    # Build table with fixed widths to avoid header wrapping
    tbl = Table(rows, repeatRows=1, colWidths=col_widths)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), HEADER_TXT),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), STRIPE),
        ("GRID", (0, 0), (-1, -1), 0.25, GRID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),  # row numbers
        ("ALIGN", (table_col_align["frames_col"], 1), (table_col_align["frames_col"], -1), "RIGHT"),
        ("ALIGN", (table_col_align["dbm_start"], 1), (table_col_align["dbm_end"], -1), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))

    # Subtle mark for low-sample rows (Frames < 5)
    LOW = colors.HexColor("#6B7280")
    for ridx, r in enumerate(rows[1:], start=1):  # skip header
        try:
            frames_n = int(r[table_col_align["frames_col"]])
        except Exception:
            frames_n = 0
        if frames_n < MIN_FRAMES_FOR_CHART:
            tbl.setStyle(TableStyle([
                ("TEXTCOLOR", (table_col_align["frames_col"], ridx), (table_col_align["frames_col"], ridx), LOW),
            ]))

    # Color Min/Avg/Max dBm cells per row (green/amber/red)
    for ridx, r in enumerate(rows[1:], start=1):  # skip header
        for c in range(table_col_align["dbm_start"], table_col_align["dbm_end"] + 1):
            col = _dbm_color(_to_float(r[c]))
            if col:
                tbl.setStyle(TableStyle([
                    ("TEXTCOLOR", (c, ridx), (c, ridx), col),
                ]))

    story += [Paragraph(f"<b>{section_title}</b>", styles["Heading2"]), Spacer(1, 6), tbl, Spacer(1, 8)]

    # Footnote for clarity
    foot = ("<i>Notes:</i> RSSI in dBm is usually negative; "
            "<b>Max</b> (closer to 0) ≈ strongest; <b>Min</b> (more negative) ≈ weakest. "
            "<b>Frames (n)</b> is the sample size; rows with n &lt; 5 are low confidence for RSSI statistics.")
    story += [Paragraph(foot, ParagraphStyle("foot", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor('#555555')))]

    # --- Per-Frame Details (last 25) ---
    pf = per_frame_view(df, limit=25)
    if not pf.empty:
        col_order = []
        for c in ["time", "timestamp"]:
            if c in pf.columns: col_order.append(c)
        for c in ["src_mac", "srcMac"]:
            if c in pf.columns: col_order.append(c)
        for c in ["dst_mac", "dstMac"]:
            if c in pf.columns: col_order.append(c)
        for c in ["SSID", "ssid", "encType", "enc_type", "authMode", "auth_mode", "contentLength", "content_length", "strength", "rssi"]:
            if c in pf.columns and c not in col_order:
                col_order.append(c)

        header_map = {
            "time": "Time", "timestamp": "Time",
            "src_mac": "Src MAC", "srcMac": "Src MAC",
            "dst_mac": "Dst MAC", "dstMac": "Dst MAC",
            "SSID": "SSID", "ssid": "SSID",
            "encType": "encType", "enc_type": "encType",
            "authMode": "Auth", "auth_mode": "Auth",
            "contentLength": "Len", "content_length": "Len",
            "strength": "dBm", "rssi": "dBm",
        }

        pf_rows = [[header_map.get(c, c) for c in col_order]]
        for _, r in pf.iterrows():
            pf_rows.append([str(r.get(c, ""))[:24] for c in col_order])

        pf_tbl = Table(pf_rows, repeatRows=1)
        pf_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
            ("GRID", (0, 0), (-1, -1), 0.25, GRID),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story += [Spacer(1, 10), Paragraph("<b>Per-Frame Details (last 25)</b>", styles["Heading2"]), Spacer(1, 4), pf_tbl]

    # ---- Build ----
    def _header_footer(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - 20*mm, 12*mm, f"Page {doc.page}")
        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=lambda c, d: _header_footer(c, d),
        onLaterPages=lambda c, d: _header_footer(c, d),
    )


# -----------------------
# Main
# -----------------------
def main():
    ap = argparse.ArgumentParser(description="Generate Wi-Fi PDF report from CSV or DB")

    # CSV args
    ap.add_argument("--in", dest="in_csv", help="Path to scan CSV (required if --source=csv)")
    ap.add_argument("--out", dest="out_pdf", default="reports/wifi_report.pdf")
    ap.add_argument("--title", default="Wireless Intelligence Report")
    ap.add_argument("--project", default="Team 404 – Prototype")
    ap.add_argument("--subtitle", default="Prototype report")
    ap.add_argument("--filter-ssid", default="")
    ap.add_argument("--app-version", default="0.1.0")
    ap.add_argument("--capture-mode", default="monitor", help="monitor | managed")

    # Branding / logo
    ap.add_argument("--logo", dest="logo_path", help="Path to PNG/JPG logo (transparent or white background recommended)")
    ap.add_argument("--logo-align", choices=["left", "center", "right"], default="center")
    ap.add_argument("--logo-max-width-mm", type=float, default=60.0)
    ap.add_argument("--logo-max-height-mm", type=float, default=22.0)
    ap.add_argument("--upscale-logo", dest="logo_upscale", action="store_true", help="Allow enlarging logo beyond its native size")

    # Layout
    ap.add_argument("--orientation", choices=["auto", "portrait", "landscape"], default="auto",
                    help="Page orientation. 'auto' = CSV→portrait, DB→landscape.")

    # Source switch & DB args
    ap.add_argument("--source", choices=["csv", "db"], default="csv", help="Input source: csv or db")
    ap.add_argument("--project-id", type=str, help="Project ID (or 'latest') when --source=db")
    ap.add_argument("--db-host", default="localhost")
    ap.add_argument("--db-user", default="root")
    ap.add_argument("--db-pass", default="")
    ap.add_argument("--db-name", default="team404")

    args = ap.parse_args()

    # Resolve repo/script dirs for robust logo discovery
    SCRIPT_DIR = Path(__file__).resolve().parent
    REPO_ROOT = SCRIPT_DIR.parent
    args.logo_path = _resolve_logo_path(getattr(args, "logo_path", None), SCRIPT_DIR, REPO_ROOT)
    print(f"[logo] resolved path: {args.logo_path}")

    # Decide data source
    if args.source == "csv":
        if not args.in_csv:
            raise SystemExit("Error: --in is required when --source=csv")
        df = load_scan_csv(Path(args.in_csv))
        project_meta = {"projectID": None, "type": "csv"}
        data_file_name = Path(args.in_csv).name
    else:
        if connect_db is None:
            raise SystemExit("DB modules not available. Install requirements and try again.")
        if not args.project_id:
            raise SystemExit("Error: --project-id is required when --source=db")

        conn = connect_db(args.db_host, args.db_user, args.db_pass, args.db_name)
        pid_arg = str(args.project_id).lower()
        if pid_arg in ("latest", "last"):
            if latest_project_id is None:
                raise SystemExit("latest_project_id helper not available.")
            pid = latest_project_id(conn)
            if pid is None:
                raise SystemExit("No projects in DB; seed with smoke_insert.py")
        else:
            pid = int(args.project_id)

        project_meta = fetch_project_metadata(conn, pid)
        df = fetch_ingest_as_analysis_df(conn, pid)
        data_file_name = "(database)"

    # Pagesize decision (portrait/landscape)
    if args.orientation == "portrait":
        pagesize = A4
    elif args.orientation == "landscape":
        pagesize = landscape(A4)
    else:  # auto
        pagesize = landscape(A4) if args.source == "db" else A4

    meta = {
        "title": args.title,
        "project": args.project,
        "subtitle": args.subtitle,
        "filter_ssid": args.filter_ssid,
        "app_version": args.app_version,
        "project_meta": project_meta,
        "data_file_name": data_file_name,
        "capture_mode": args.capture_mode,
        "logo_path": args.logo_path,
        "logo_align": args.logo_align,
        "logo_max_width_mm": args.logo_max_width_mm,
        "logo_max_height_mm": args.logo_max_height_mm,
        "logo_upscale": bool(getattr(args, "logo_upscale", False)),
        "pagesize": pagesize,
    }

    # Auto-name the output for DB runs unless the user provided a custom name
    if args.source == "db" and args.out_pdf in ("reports/wifi_report.pdf", "reports\\wifi_report.pdf"):
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_type = str(project_meta.get("type", "db")).replace("/", "-")
        out = Path(f"reports/{project_meta['projectID']}-{safe_type}-{stamp}.pdf")
    else:
        out = Path(args.out_pdf)

    out.parent.mkdir(parents=True, exist_ok=True)

    build_pdf(df, out, meta, args.source)
    print(f"Report written to: {out.resolve()}")


if __name__ == "__main__":
    main()
