import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from databaseMain.databaseTemplates import get_connection


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
            COALESCE(NULLIF(srcMac, ''), 'unknown') AS mac,
            COUNT(*) AS frames,
            MIN(captureTime) AS first_seen,
            MAX(captureTime) AS last_seen,
            MIN(strength) AS min_rssi,
            ROUND(AVG(strength),1) AS avg_rssi,
            MAX(strength) AS max_rssi,
            GROUP_CONCAT(DISTINCT encType) AS enc_types,
            GROUP_CONCAT(DISTINCT authMode) AS auth_modes
        FROM IngestDB
        WHERE projectID = %s AND SSID = %s
        GROUP BY srcMac
        ORDER BY frames DESC
    """, (pid, ssid))
    macs = cur.fetchall()
    conn.close()
    return macs