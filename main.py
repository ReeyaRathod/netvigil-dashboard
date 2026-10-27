from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from vapt_scanner import run_vapt_scan
from reporter import generate_vapt_pdf

app = FastAPI(title="NetVigil VAPT Dashboard")
templates = Jinja2Templates(directory="templates")

VAPT_CACHE = {}

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
	return templates.TemplateResponse(request, "index.html", {"scan_results": None})

@app.get("/scan", response_class=HTMLResponse)
async def perform_scan(request: Request, ip: str):
	clean_ip = ip.strip()
	scan_data = run_vapt_scan(clean_ip)

	VAPT_CACHE["ip"] = clean_ip
	VAPT_CACHE["data"] = scan_data

	return templates.TemplateResponse(request, "index.html", {
		"target_ip": clean_ip,
		"scan_results": scan_data
	})

@app.get("/download-pdf")
async def download_report():
	if not VAPT_CACHE.get("data"):
		return {"error": "No assessment data available to generate report."}

	pdf_path = generate_vapt_pdf(VAPT_CACHE["ip"], VAPT_CACHE["data"])
	return FileResponse(pdf_path, filename=f"{VAPT_CACHE['ip']}_NetVigil_VAPT_Report.pdf")
