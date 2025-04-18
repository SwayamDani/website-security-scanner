import nmap

class PortScanningModule:
    def run_test(self, domain):
        findings = {}

        try:
            scanner = nmap.PortScanner()

            # Scan Top 100 common ports quickly
            scan_args = '-T4 --top-ports 100 --open'
            scanner.scan(domain, arguments=scan_args)

            if domain in scanner.all_hosts():
                for proto in scanner[domain].all_protocols():
                    lport = scanner[domain][proto].keys()
                    for port in sorted(lport):
                        findings[port] = scanner[domain][proto][port]['name']
            else:
                findings["Info"] = "No open ports found."

        except Exception as e:
            return {
                "module": "Port Scanning",
                "error": str(e)
            }

        return {
            "module": "Port Scanning",
            "findings": findings
        }
