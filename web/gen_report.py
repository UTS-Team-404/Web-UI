from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from pathlib import Path
from databaseMain.databaseTemplates import get_connection
from db_utils_web import get_ssid_counts, get_macs_by_ssid, get_ssids # import your functions

def generate_pdf_report(project_id: int, ssid_filter: str | None = None, output_path: Path = Path("report.pdf")):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Fetch SSID counts (SSID + total frames)
    ssids = get_ssid_counts(project_id)
    if ssid_filter:
        ssids = [s for s in ssids if s[0] == ssid_filter]

    doc = SimpleDocTemplate(str(output_path), pagesize=landscape(A4))
    elements = []
    styles = getSampleStyleSheet()

    # Title
    elements.append(Paragraph(f"Wi-Fi Analysis Report – Project {project_id}", styles['Title']))
    elements.append(Spacer(1, 12))

    for ssid, frames in ssids:
        elements.append(Paragraph(f"SSID: {ssid} – Total Frames: {frames}", styles['Heading2']))
        elements.append(Spacer(1, 6))

        macs = get_macs_by_ssid(project_id, ssid)
        if not macs:
            elements.append(Paragraph("No MAC data found.", styles['Normal']))
            elements.append(Spacer(1, 12))
            continue

        data = [["MAC", "Frames", "First Seen", "Last Seen", "Min RSSI", "Avg RSSI", "Max RSSI", "Enc Types", "Auth Modes"]]
        for mac in macs:
            data.append([
                mac['mac'], mac['frames'], str(mac['first_seen']), str(mac['last_seen']),
                mac['min_rssi'], mac['avg_rssi'], mac['max_rssi'], mac['enc_types'], mac['auth_modes']
            ])

        table = Table(data, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('ALIGN',(0,0),(-1,-1),'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.black),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold')
        ]))
        elements.append(table)
        elements.append(Spacer(1, 24))

    doc.build(elements)
    print(f"Report written to {output_path.resolve()}")
