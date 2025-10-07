# report/wifi_analysis.py
from dataclasses import dataclass
from typing import Dict, Tuple
import pandas as pd
import numpy as np


@dataclass
class TimeWindow:
    start_ms: int
    end_ms: int
    duration_s: float


# ---------- small internal helpers ----------
def _first_present(df: pd.DataFrame, candidates: list[str]) -> str | None:
    """Return the first column name that exists in df."""
    for c in candidates:
        if c in df.columns:
            return c
    return None


def _top_mode(s: pd.Series) -> str:
    """Return most frequent non-null value as string (safe)."""
    s = s.dropna()
    if s.empty:
        return ""
    try:
        return str(s.mode().iloc[0])
    except Exception:
        vc = s.value_counts()
        return str(vc.index[0]) if len(vc) else ""


# ---------- analytics used by the report ----------
def compute_time_window(df: pd.DataFrame) -> TimeWindow:
    t0 = int(pd.to_numeric(df["timestamp_ms"], errors="coerce").min())
    t1 = int(pd.to_numeric(df["timestamp_ms"], errors="coerce").max())
    return TimeWindow(t0, t1, max(0.0, (t1 - t0) / 1000.0))


def frame_size_stats(df: pd.DataFrame) -> Dict[str, float]:
    arr = pd.to_numeric(df["frame_len"], errors="coerce").dropna().astype("int32")
    if arr.empty:
        return {"min": 0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0, "count": 0, "bytes_total": 0}
    return {
        "min": int(arr.min()),
        "p50": float(np.percentile(arr, 50)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
        "max": int(arr.max()),
        "count": int(arr.size),
        "bytes_total": int(arr.sum()),
    }


def interarrival_stats(df: pd.DataFrame) -> Dict[str, float]:
    s = (
        df.sort_values("timestamp_ms")["timestamp_ms"]
        .pipe(pd.to_numeric, errors="coerce")
        .diff()
        .dropna()
    )
    if s.empty:
        return {"mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0}
    return {
        "mean_ms": float(s.mean()),
        "p50_ms": float(np.percentile(s, 50)),
        "p95_ms": float(np.percentile(s, 95)),
    }


def beacon_summary(df: pd.DataFrame) -> pd.DataFrame:
    subtype = df.get("subtype")
    frame_type = df.get("frame_type")
    if subtype is None or frame_type is None:
        return pd.DataFrame(columns=["ssid", "channel", "bssid_count", "beacon_count", "hidden"])
    beacons = df[
        (frame_type == "mgmt") &
        (subtype.astype(str).str.lower() == "beacon")
    ]
    if beacons.empty:
        return pd.DataFrame(columns=["ssid", "channel", "bssid_count", "beacon_count", "hidden"])
    grp = beacons.groupby(["ssid", "channel"], dropna=False)
    res = grp.agg(
        bssid_count=("bssid", pd.Series.nunique),
        beacon_count=("bssid", "count"),
    ).reset_index()
    res["hidden"] = res["ssid"].fillna("").eq("") | res["ssid"].astype(str).str.contains("hidden", case=False, na=False)
    return res.sort_values(["hidden", "beacon_count"], ascending=[False, False])


def infer_aps(df: pd.DataFrame) -> pd.DataFrame:
    subtype = df.get("subtype")
    frame_type = df.get("frame_type")
    if subtype is None or frame_type is None:
        return pd.DataFrame(columns=["ap_bssid", "ssid", "channel", "beacon_count"])
    beacons = df[
        (frame_type == "mgmt") &
        (subtype.astype(str).str.lower() == "beacon")
    ]
    if beacons.empty:
        return pd.DataFrame(columns=["ap_bssid", "ssid", "channel", "beacon_count"])
    aps = beacons.groupby("bssid", dropna=False).agg(
        ssid=("ssid", lambda x: x.dropna().iloc[0] if len(x.dropna()) else ""),
        channel=("channel", lambda x: x.dropna().iloc[0] if len(x.dropna()) else np.nan),
        beacon_count=("bssid", "count"),
    ).reset_index().rename(columns={"bssid": "ap_bssid"})
    return aps


def talkers(df: pd.DataFrame, top_n: int = 10) -> Tuple[pd.DataFrame, pd.DataFrame]:
    frames_by_src = (
        df.groupby("src_mac", dropna=False)
        .size()
        .reset_index(name="frames")
        .sort_values("frames", ascending=False)
        .head(top_n)
    )
    bytes_by_src = (
        df.groupby("src_mac", dropna=False)["frame_len"]
        .sum()
        .reset_index(name="bytes")
        .sort_values("bytes", ascending=False)
        .head(top_n)
    )
    return frames_by_src, bytes_by_src


def mac_pairs(df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    if not set(["src_mac", "dst_mac"]).issubset(df.columns):
        return pd.DataFrame(columns=["src_mac", "dst_mac", "frames"])
    pairs = (
        df.groupby(["src_mac", "dst_mac"], dropna=False)
        .size()
        .reset_index(name="frames")
        .sort_values("frames", ascending=False)
    )
    return pairs.head(top_n)


def rts_cts_stats(df: pd.DataFrame) -> Dict[str, float]:
    subtype = df.get("subtype")
    frame_type = df.get("frame_type")
    if subtype is None or frame_type is None:
        return {"rts_count": 0, "cts_count": 0, "match_rate": 0.0}

    sub = subtype.astype(str).str.lower()
    rts = df[(frame_type == "ctrl") & (sub == "rts")]
    cts = df[(frame_type == "ctrl") & (sub == "cts")]
    stats = {
        "rts_count": int(len(rts)),
        "cts_count": int(len(cts)),
        "match_rate": 0.0,
    }
    if rts.empty or cts.empty:
        return stats

    rts_tmp = rts[["timestamp_ms", "src_mac", "dst_mac"]].copy()
    cts_tmp = cts[["timestamp_ms", "src_mac", "dst_mac"]].copy()
    rts_tmp["key"] = rts_tmp["src_mac"].astype(str) + ">" + rts_tmp["dst_mac"].astype(str)
    cts_tmp["key_rev"] = cts_tmp["src_mac"].astype(str) + ">" + cts_tmp["dst_mac"].astype(str)

    cts_idx = cts_tmp.set_index("key_rev")
    matches = 0
    for _, row in rts_tmp.iterrows():
        key_rev = f"{row['dst_mac']}>{row['src_mac']}"
        if key_rev in cts_idx.index:
            sel = cts_idx.loc[[key_rev]] if isinstance(cts_idx.loc[key_rev], pd.DataFrame) else pd.DataFrame([cts_idx.loc[key_rev]])
            dt_min = (pd.to_numeric(sel["timestamp_ms"], errors="coerce") - pd.to_numeric(row["timestamp_ms"], errors="coerce")).abs().min()
            if pd.notna(dt_min) and dt_min <= 5:  # 5 ms window
                matches += 1

    if len(rts_tmp) > 0:
        stats["match_rate"] = round(matches / len(rts_tmp), 3)
    return stats


def ap_client_links(df: pd.DataFrame, aps_df: pd.DataFrame) -> pd.DataFrame:
    if aps_df is None or aps_df.empty or "ap_bssid" not in aps_df.columns:
        return pd.DataFrame(columns=["ssid", "channel", "ap_bssid", "client_mac", "frames"])
    ap_set = set(aps_df["ap_bssid"].tolist())
    data = df[df.get("frame_type", "") == "data"].copy()
    if data.empty or "bssid" not in data.columns:
        return pd.DataFrame(columns=["ssid", "channel", "ap_bssid", "client_mac", "frames"])

    data = data[data["bssid"].isin(ap_set)]
    rows = []
    for _, r in data.iterrows():
        ap = r["bssid"]
        if r.get("src_mac") is not None and r["src_mac"] != ap:
            rows.append((ap, r["src_mac"]))
        if r.get("dst_mac") is not None and r["dst_mac"] != ap:
            rows.append((ap, r["dst_mac"]))

    if not rows:
        return pd.DataFrame(columns=["ssid", "channel", "ap_bssid", "client_mac", "frames"])

    pairs = pd.DataFrame(rows, columns=["ap_bssid", "client_mac"]).value_counts().reset_index(name="frames")
    out = pairs.merge(aps_df[["ap_bssid", "ssid", "channel"]], on="ap_bssid", how="left")
    return out.sort_values("frames", ascending=False)


# ---------- assessor-requested helpers used by the PDF ----------
def mac_summary_enhanced(df: pd.DataFrame) -> pd.DataFrame:
    """
    Per-MAC summary including SSID, encType, authMode, and average content length.
    Works with both snake_case and camelCase columns.
    """
    mac_col = _first_present(df, ["src_mac", "srcMac", "bssid", "mac", "dst_mac", "dstMac"])
    tmp = df.copy()
    if mac_col is None:
        tmp["mac_tmp"] = "(unknown)"
        mac_col = "mac_tmp"

    # timestamps
    if "timestamp_ms" in tmp.columns:
        ts = pd.to_datetime(tmp["timestamp_ms"], unit="ms", errors="coerce")
    else:
        tcol = _first_present(tmp, ["time", "timestamp"])
        ts = pd.to_datetime(tmp[tcol], errors="coerce") if tcol else pd.Series([pd.NaT] * len(tmp))

    # strength
    rssi_col = _first_present(tmp, ["strength", "rssi"])
    rssi = pd.to_numeric(tmp[rssi_col], errors="coerce") if rssi_col else pd.Series([pd.NA] * len(tmp))

    # extra fields
    ssid_col = _first_present(tmp, ["SSID", "ssid"])
    enc_col  = _first_present(tmp, ["encType", "enc_type"])
    auth_col = _first_present(tmp, ["authMode", "auth_mode"])
    len_col  = _first_present(tmp, ["contentLength", "content_length", "len", "length"])

    g = pd.DataFrame({"mac": tmp[mac_col], "ts": ts, "rssi": rssi})
    if ssid_col: g["ssid"] = tmp[ssid_col]
    if enc_col:  g["encType"] = tmp[enc_col]
    if auth_col: g["authMode"] = tmp[auth_col]
    if len_col:  g["contentLength"] = pd.to_numeric(tmp[len_col], errors="coerce")

    base = g.groupby("mac", dropna=False).agg(
        frames=("mac", "size"),
        first_seen=("ts", "min"),
        last_seen=("ts", "max"),
        min_rssi=("rssi", "min"),
        avg_rssi=("rssi", "mean"),
        max_rssi=("rssi", "max"),
    )

    base["ssid"] = g.groupby("mac")["ssid"].agg(_top_mode) if "ssid" in g.columns else ""
    base["encType"] = g.groupby("mac")["encType"].agg(_top_mode) if "encType" in g.columns else ""
    base["authMode"] = g.groupby("mac")["authMode"].agg(_top_mode) if "authMode" in g.columns else ""
    base["avg_len"] = g.groupby("mac")["contentLength"].mean().round(0) if "contentLength" in g.columns else pd.NA

    out = base.reset_index().rename(columns={"mac": "bssid"})
    out["avg_rssi"] = out["avg_rssi"].round(1)
    return out.sort_values(["frames", "bssid"], ascending=[False, True])


def per_frame_view(df: pd.DataFrame, limit: int = 25) -> pd.DataFrame:
    """
    Return a small per-frame slice showing SSID / encType / authMode / contentLength / dBm next to each frame.
    """
    time_col = _first_present(df, ["time", "timestamp"])
    src_col  = _first_present(df, ["src_mac", "srcMac"])
    dst_col  = _first_present(df, ["dst_mac", "dstMac"])
    ssid_col = _first_present(df, ["SSID", "ssid"])
    enc_col  = _first_present(df, ["encType", "enc_type"])
    auth_col = _first_present(df, ["authMode", "auth_mode"])
    len_col  = _first_present(df, ["contentLength", "content_length", "len", "length"])
    dbm_col  = _first_present(df, ["strength", "rssi"])

    cols = [c for c in [time_col, src_col, dst_col, ssid_col, enc_col, auth_col, len_col, dbm_col] if c]
    if not cols:
        return pd.DataFrame()

    view = df[cols].copy()
    if time_col:
        view = view.sort_values(time_col)
    return view.tail(limit).reset_index(drop=True)
