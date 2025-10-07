from pathlib import Path
from flask import Flask, render_template, request

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from databaseMain.databaseTemplates import get_connection

CSV_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_scan.csv"

# Database Functions

def get_projects():
   conn=get_connection()
   cur = conn.cursor()

   cur.execute("SELECT DISTINCT(projectID) FROM IngestDB")
   projects = [row[0] for row in cur.fetchall()]
   conn.close()
   return projects


def get_ssids(pid):
   conn=get_connection()
   cur = conn.cursor()

   cur.execute("SELECT DISTINCT(SSID) FROM IngestDB WHERE projectID = %s",
        (pid,)
    )
   ssids = [row[0] for row in cur.fetchall()]
   conn.close()
   return ssids

def get_data(pid, q):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    query = """
        SELECT * FROM IngestDB
        WHERE projectID = %s
    """
    params = [pid]

    if q:
        query += " AND ssid LIKE %s"
        params.append(f"%{q}%")

    cur.execute(query, params)
    data = cur.fetchall()
    conn.close()
    return data

def get_ssid_counts(pid):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT SSID, COUNT(*) AS frames
        FROM IngestDB
        WHERE projectID = %s
        GROUP BY SSID
        ORDER BY frames DESC
    """, (pid,))
    ssids = cur.fetchall() 
    conn.close()
    return ssids


def get_macs_by_ssid(pid, ssid):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT 
            srcMac AS mac,
            COUNT(*) AS frames,
            MIN(captureTime) AS first_seen,
            MAX(captureTime) AS last_seen,
            MIN(strength) AS min_rssi,
            ROUND(AVG(strength),1) AS avg_rssi,
            MAX(strength) AS max_rssi
        FROM IngestDB
        WHERE projectID = %s AND SSID = %s
        GROUP BY srcMac
        ORDER BY frames DESC
    """, (pid, ssid))
    macs = cur.fetchall()
    conn.close()
    return macs


app = Flask(__name__)

@app.route("/")
def index():
  pid = request.args.get("pid")
  q = request.args.get("q")

  project_ids = get_projects()
  ssids = get_ssids(pid) if pid else []
  data = get_data(pid, q) if pid else []
  macs = get_macs_by_ssid(pid, q) if q else None


  return render_template(
    "index.html",
    project_ids=project_ids,
    ssids=ssids,
    selected_pid=pid,
    selected_q=q,
    data=data,
    macs=macs
  )

@app.route("/heatmap.html")
def heatmap():
   return render_template(
      "heatmap_output.html"
   )
  
#  ssid_counts = df.groupby("ssid").size().sort_values(ascending=False)
#  ssids = list(ssid_counts.items())
#  return render_template("index.html", ssids=ssids, macs=None, selected=None, project_ids=project_ids, q=q)


# @app.route("/ssid/<ssid>")
# def ssid_view(ssid):
#   df = load_df()
#   df = df[df["ssid"].fillna("") == ssid]
#   g = df.groupby("bssid")
#   agg = g.agg(frames=("bssid","size"),
#               first_seen=("timestamp","min"),
#               last_seen=("timestamp","max"),
#               min_rssi=("rssi","min"),
#               avg_rssi=("rssi","mean"),
#               max_rssi=("rssi","max"),
#               channels=("channel", lambda s: ", ".join(sorted(set(s.astype(str))))))
#   rows = []
#   for mac, r in agg.sort_values("frames", ascending=False).iterrows():
#       rows.append({
#           "bssid": mac,
#           "frames": int(r["frames"]),
#           "first_seen": r["first_seen"],
#           "last_seen": r["last_seen"],
#           "channels": r["channels"],
#           "min_rssi": r["min_rssi"],
#           "avg_rssi": round(r["avg_rssi"],1) if pd.notna(r["avg_rssi"]) else "",
#           "max_rssi": r["max_rssi"],
#       })
#   ssid_counts = df.groupby("ssid").size().sort_values(ascending=False)
#   ssids = list(ssid_counts.items())
#   return render_template("index.html", ssids=ssids, macs=rows, selected=ssid, q=None)
# test
if __name__ == "__main__":
  app.run(debug=True, port=5001)