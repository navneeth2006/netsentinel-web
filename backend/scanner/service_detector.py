# Light banner grabber for common services
import socket

COMMON_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,587,3306,3389,8080]

def grab_banner(host, port, timeout=1.5):
    try:
        with socket.socket() as s:
            s.settimeout(timeout)
            s.connect((host, port))
            # For HTTP, send minimal request
            if port in (80, 8080, 8000):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            try:
                data = s.recv(1024)
                return data.decode('utf-8', errors='ignore').strip()
            except Exception:
                return ""
    except Exception:
        return ""
