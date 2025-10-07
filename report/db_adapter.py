# report/db_adapter.py
import mysql.connector as mc
import pandas as pd

def connect_db(host: str, user: str, password: str, database: str, port: int = 3306):
    """Open a MariaDB/MySQL connection."""
    # 127.0.0.1 is safer than 'localhost' on Windows
    host = "127.0.0.1" if host in ("localhost", "127.0.0.1") else host
    return mc.connect(host=host, user=user, password=password, database=database, port=port)

def fetch_project_metadata(conn, project_id: int) -> dict:
    """Return {projectID, startTime, stopTime, type} for the report header."""
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT ID AS projectID, startTime, stopTime, projectType AS type
        FROM ProjectDB WHERE ID=%s
    """, (project_id,))
    row = cur.fetchone()
    cur.close()
    if not row:
        raise ValueError(f"Project {project_id} not found")
    return row

def fetch_ingest_as_analysis_df(conn, project_id: int) -> pd.DataFrame:
    """
    Return a DataFrame shaped for your report/analysis code.
    We keep column names your report already understands.
    """
    q = """
    SELECT
      ID,
      projectID,
      captureTime,
      srcMac  AS src_mac,
      dstMac  AS dst_mac,
      SSID    AS ssid,
      encType AS enc_type,
      authMode AS auth_mode,
      gpsLat  AS gps_lat,
      gpsLong AS gps_long,
      strength,
      contentLength AS frame_len,
      typeExternal  AS type_external,
      typeInternal  AS type_internal,
      srcIP   AS src_ip,
      dstIP   AS dst_ip,
      srcPort AS src_port,
      dstPort AS dst_port,
      sniffType AS sniff_type
    FROM IngestDB
    WHERE projectID = %s
    ORDER BY captureTime
    """
    df = pd.read_sql(q, conn, params=[project_id])

    # Add timestamp_ms column expected by parts of the analysis
    if "captureTime" in df.columns:
        ts = pd.to_datetime(df["captureTime"], errors="coerce")
        df["timestamp_ms"] = (ts.astype("int64") // 1_000_000)  # ns->ms

    # Optional columns some sections check for:
    if "frame_type" not in df.columns:
        df["frame_type"] = pd.NA
    if "subtype" not in df.columns:
        df["subtype"] = pd.NA

    return df

# (handy for you while testing)
def latest_project_id(conn) -> int | None:
    cur = conn.cursor()
    cur.execute("SELECT MAX(ID) FROM ProjectDB")
    pid = cur.fetchone()[0]
    cur.close()
    return pid
