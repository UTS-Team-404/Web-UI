import mysql.connector
from datetime import datetime
from pathlib import Path

# Database configuration
DB_CONFIG = {
    'host': '127.0.0.1',   # use 127.0.0.1 on Windows
    'port': 3306,
    'database': 'team404',
    'user': 'team404user',
    'password': 'pass',
    'charset': 'utf8mb4',
}

def get_connection():
    """Return a new database connection."""
    return mysql.connector.connect(**DB_CONFIG)

# ---------------- ProjectDB Functions ---------------- #

def create_project(start_time: str, project_type: str):
    """
    Insert a new project into ProjectDB.
    start_time: "YYYY-MM-DD HH:MM:SS"
    project_type: one of ('sniff_external', 'sniff_internal', 'heatmap')
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO ProjectDB (startTime, projectType)
        VALUES (%s, %s)
    """, (start_time, project_type))
    conn.commit()
    project_id = cur.lastrowid
    conn.close()
    return project_id

def stop_project(project_id: int, stop_time: str):
    """Update a project to set its stop time."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE ProjectDB
        SET stopTime = %s
        WHERE ID = %s
    """, (stop_time, project_id))
    conn.commit()
    conn.close()

def get_projects():
    """Return all projects."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ProjectDB")
    rows = cur.fetchall()
    conn.close()
    return rows

# ---------------- IngestDB Functions ---------------- #

def insert_sniff_external(
    project_id: int,
    capture_time: str,
    src_mac: str,
    dst_mac: str = None,
    ssid: str = None,
    enc_type: str = None,
    auth_mode: str = None,
    strength: int = None,
    content_length: int = None,
    type_external: str = None
):
    """Insert a row into IngestDB for external (monitor-mode) capture."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO IngestDB (
            projectID, captureTime, srcMac, dstMac, SSID, encType, authMode,
            strength, contentLength, typeExternal, sniffType
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        project_id, capture_time, src_mac, dst_mac, ssid, enc_type, auth_mode,
        strength, content_length, type_external, 'external'
    ))
    conn.commit()
    ingest_id = cur.lastrowid
    conn.close()
    return ingest_id

def insert_sniff_internal(
    project_id: int,
    capture_time: str,
    src_mac: str,
    dst_mac: str = None,
    ssid: str = None,
    enc_type: str = None,
    auth_mode: str = None,
    strength: int = None,
    content_length: int = None,
    type_internal: str = None,
    src_ip: str = None,
    dst_ip: str = None,
    src_port: int = None,
    dst_port: int = None,
    sniff_type: str = 'internal'
):
    """Insert a row into IngestDB for internal/promiscuous capture."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO IngestDB (
            projectID, captureTime, srcMac, dstMac, SSID, encType, authMode,
            strength, contentLength, typeInternal, srcIP, dstIP, srcPort, dstPort, sniffType
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        project_id, capture_time, src_mac, dst_mac, ssid, enc_type, auth_mode,
        strength, content_length, type_internal, src_ip, dst_ip, src_port, dst_port, sniff_type
    ))
    conn.commit()
    ingest_id = cur.lastrowid
    conn.close()
    return ingest_id

def insert_heatmap(
    project_id: int,
    capture_time: str,
    src_mac: str,
    ssid: str = None,
    gps_lat: float = None,
    gps_long: float = None,
    strength: int = None,
):
    """Insert a heatmap measurement (casts GPS to INT to match schema)."""
    conn = get_connection()
    cur = conn.cursor()
    lat = int(gps_lat) if gps_lat is not None else None
    lng = int(gps_long) if gps_long is not None else None
    cur.execute("""
        INSERT INTO IngestDB (
            projectID, captureTime, srcMac, SSID, gpsLat, gpsLong, strength
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (project_id, capture_time, src_mac, ssid, lat, lng, strength))
    conn.commit()
    ingest_id = cur.lastrowid
    conn.close()
    return ingest_id

def get_ingests_by_project(project_id: int):
    """Fetch all ingests for a given project."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM IngestDB WHERE projectID = %s", (project_id,))
    rows = cur.fetchall()
    conn.close()
    return rows

def get_ingests_by_mac(mac: str):
    """Fetch ingests by source/dest MAC."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM IngestDB WHERE srcMac = %s OR dstMac = %s", (mac, mac))
    rows = cur.fetchall()
    conn.close()
    return rows

# --------- Initialise schema from ./databaseCreate.sql (same folder) ---------

def init_db(schema_file="databaseCreate.sql"):
    """
    Initialize the database using schema from an external SQL file.
    Looks for the SQL file next to this .py.
    """
    sql_path = Path(__file__).parent / schema_file
    if not sql_path.exists():
        raise FileNotFoundError(f"Schema file '{sql_path}' not found.")
    schema_sql = sql_path.read_text(encoding="utf-8")

    conn = get_connection()
    cur = conn.cursor()
    statements = [s.strip() for s in schema_sql.split(';') if s.strip()]
    for stmt in statements:
        cur.execute(stmt)
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

def get_table_schema(table_name: str):
    """Get table schema information."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, EXTRA
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
        ORDER BY ORDINAL_POSITION
    """, (DB_CONFIG['database'], table_name))
    rows = cur.fetchall()
    conn.close()
    return rows

if __name__ == "__main__":
    init_db()
    print(get_table_schema("ProjectDB"))
    print(get_table_schema("IngestDB"))
