from datetime import datetime
import databaseTemplates as dbt   # same folder import

now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# 1) start a project
pid = dbt.create_project(now, "sniff_external")
print("ProjectID:", pid)

# 2) insert one fake capture row so the project has data
dbt.insert_sniff_external(
    project_id=pid,
    capture_time=now,
    src_mac="aa:bb:cc:dd:ee:ff",
    dst_mac="ff:ee:dd:cc:bb:aa",
    ssid="TestSSID",
    enc_type="WPA2",
    auth_mode="PSK",
    strength=-48,
    content_length=0,
    type_external="Broadcast",
)

# 3) stop the project
dbt.stop_project(pid, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
print("Inserted one row and closed project.")
