from pathlib import Path
from flask import Flask, render_template, request, send_file
from db_utils_web import *
from gen_report import generate_pdf_report

from pathlib import Path

BASE_DIR = Path(__file__).parent 
REPORTS_DIR = BASE_DIR / "static" / "reports"

app = Flask(__name__)

@app.route("/")
def index():
  pid = request.args.get("pid")
  q = request.args.get("q")

  project_ids = get_projects()
  ssids = get_ssids(pid) if pid else []
  macs = get_macs_by_ssid(pid, q) if q else None


  return render_template(
    "index.html",
    project_ids=project_ids,
    ssids=ssids,
    selected_pid=pid,
    selected_q=q,
    macs=macs
  )

@app.route("/download_report")
def download_report():

    project_id = int(request.args.get("projectID", 0))
    ssid = request.args.get("ssid")  # optional
    out_pdf = Path(__file__).parent / "static" / "reports" / f"project_{project_id}.pdf"

    generate_pdf_report(project_id, ssid_filter=ssid, output_path=out_pdf)
    return send_file(out_pdf, as_attachment=True, download_name=f"report_{project_id}.pdf")

@app.route("/heatmap.html")
def heatmap():
   return render_template(
      "heatmap_output.html"
   )
  
if __name__ == "__main__":
  app.run(debug=True, port=5001)