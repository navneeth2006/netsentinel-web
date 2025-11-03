from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import socket, ipaddress, os, uuid
from scanner.port_scanner import quick_scan
from scanner.service_detector import grab_banner, COMMON_PORTS
from scanner.lan_scanner import sweep_subnet_tcp, arp_scan
from report_generator import generate_html_report

app = FastAPI(title="NetSentinel API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCAN_STORE = {}

class ScanRequest(BaseModel):
    target: str = None   # domain or ip or subnet
    type: str = "host"   # 'host' or 'subnet'
    ports: list = None

@app.post("/api/scan")
async def start_scan(req: ScanRequest, background: BackgroundTasks):
    if not req.target:
        return {"error":"target required"}
    scan_id = str(uuid.uuid4())
    SCAN_STORE[scan_id] = {"status":"queued", "result":None}
    background.add_task(run_scan, scan_id, req)
    return {"scan_id": scan_id}

@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    return SCAN_STORE.get(scan_id, {"error":"unknown scan id"})

def run_scan(scan_id, req):
    SCAN_STORE[scan_id]["status"] = "running"
    try:
        ports_to_scan = req.ports or COMMON_PORTS
        findings = {}
        if req.type == "subnet":
            # try lightweight TCP sweep
            hosts = sweep_subnet_tcp(req.target)
            findings['hosts'] = hosts
            ports_map = {}
            banners = {}
            for h in hosts:
                ports_map[h] = quick_scan(h, ports_to_scan)
                # grab banners for open ports
                for p, open_ in ports_map[h].items():
                    if open_:
                        banners.setdefault(h, {})[p] = grab_banner(h, p)
            findings['ports'] = ports_map
            findings['banners'] = banners
        else:
            # single host scan
            host = req.target
            # resolve if domain
            try:
                ip = socket.gethostbyname(host)
            except Exception:
                ip = host
            findings['host_ip'] = ip
            findings['ports'] = quick_scan(ip, ports_to_scan)
            banners = {}
            for p, open_ in findings['ports'].items():
                if open_:
                    banners[p] = grab_banner(ip, p)
            findings['banners'] = banners

        # generate report
        outpath = f"reports/report_{scan_id}.html"
        os.makedirs("reports", exist_ok=True)
        generate_html_report(req.target, findings.get('hosts', []), findings.get('ports', {}), findings.get('banners', {}), outpath=outpath)

        SCAN_STORE[scan_id] = {"status":"done", "result": findings, "report": outpath}
    except Exception as e:
        SCAN_STORE[scan_id] = {"status":"error", "error": str(e)}
