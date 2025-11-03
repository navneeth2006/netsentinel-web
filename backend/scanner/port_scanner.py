# Simple TCP connect port scanner (non-intrusive)
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(host, port, timeout=0.8):
    """Return True if port open (TCP connect)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((host, port))
            return port, (res == 0)
    except Exception:
        return port, False

def quick_scan(host, ports, workers=60):
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, host, p): p for p in ports}
        for fut in as_completed(futures):
            p, open_ = fut.result()
            results[p] = open_
    return results
