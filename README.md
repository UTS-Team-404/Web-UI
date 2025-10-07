# Team 404 — Wi-Fi Intel (Week 6 Prototype)

## What this is
- Minimal **Web UI**: lists SSIDs -> shows MACs per SSID with frames & RSSI.
- **PDF report (Python/ReportLab)**: title, **Parameters** block, and **Observed MAC Addresses** table.

## CSV format expected
`timestamp, ssid, bssid, channel, rssi`

## How to run (Windows)
```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Generate PDF (use your CSV file name)
python report\generate_report.py --in data\sample_scan.csv --out reports\wifi_report.pdf --title "Team 404 Wi-Fi Intel – Prototype Report" --project "Week 6 – Web UI + MAC Table" --filter-ssid "UTS-WiFi" --app-version "0.1.0"

# Run Web UI
python web\app.py   # then open http://127.0.0.1:5001/


# If using macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python report/generate_report.py --in data/sample_scan.csv --out reports/wifi_report.pdf
python web/app.py # then open http://127.0.0.1:5001/
