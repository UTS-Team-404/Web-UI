# Team 404 — Web UI

# Changelog
# - Fixed the glitch where rows will not continue to be displayed when a row does not have a MAC Address
# - Added Encryption and Authentication Columns
# - Separated RSSI values by columns
# - Created a PDF Generator that can take show data based on Project IDs and SSIDs
# - When SSID is not chosen in the Web UI, when download PDF is clicked, it gives a report of all the SSIDs present within the project



# Activate venv and run Web UI
source env/bin/activate
python3 .web/app.py   # then open http://127.0.0.1:5001/
