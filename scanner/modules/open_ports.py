import socket
import concurrent.futures
import time

# Common ports mapping (for human-friendly service names)
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MS RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt"
}

class PortScanningModule:
    def __init__(self, full_scan=False, stealth=False):
        self.full_scan = full_scan
        self.stealth = stealth
        self.top_ports = list(COMMON_PORTS.keys())

    def scan_port(self, target, port):
        """
        Attempts to connect to a specific port and grab the service banner if possible.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Slightly longer timeout to read banners
            result = sock.connect_ex((target, port))
            if result == 0:
                banner = ""
                try:
                    if port in [80, 8080, 443]:  # Try HTTP/HTTPS header request
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    else:
                        sock.sendall(b"Hello\r\n")
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    banner = ""

                service = COMMON_PORTS.get(port, "Unknown Service")
                if banner:
                    return f"{port} ({service}) - {banner}"
                else:
                    return f"{port} ({service})"
        except Exception:
            pass
        finally:
            sock.close()
        return None

    def run_test(self, domain):
        findings = {}

        # Step 1: Resolve domain to IP
        try:
            ip = socket.gethostbyname(domain)
        except Exception as e:
            findings["Error"] = f"Could not resolve domain {domain}: {e}"
            return {
                "module": "Port Scanning",
                "findings": findings
            }

        ports_to_scan = range(1, 65536) if self.full_scan else self.top_ports

        open_ports = []

        # Step 2: Start threaded scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {}
            for port in ports_to_scan:
                futures[executor.submit(self.scan_port, ip, port)] = port
                if self.stealth:
                    time.sleep(0.01)  # 10ms delay if stealth mode enabled

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                except Exception:
                    pass

        # Step 3: Prepare final findings
        if open_ports:
            findings["Open Ports and Services"] = open_ports
        else:
            findings["Info"] = "No open ports found."

        return {
            "module": "Port Scanning",
            "findings": findings
        }
