# scanner/modules/ssl_tls.py

import ssl
import socket
from datetime import datetime

class SSLTLSModule:
    def run_test(self, domain):
        findings = {}

        try:
            context = ssl.create_default_context()

            # Connect to domain over port 443 (HTTPS)
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()

                    # Certificate expiration check
                    not_after = cert.get('notAfter')
                    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expires - datetime.utcnow()).days

                    findings["SSL/TLS Version"] = protocol
                    findings["Certificate Expiry Date"] = expires.strftime("%Y-%m-%d")
                    findings["Days Until Expiry"] = days_left

        except Exception as e:
            return {
                "module": "SSL/TLS",
                "error": str(e)
            }

        return {
            "module": "SSL/TLS",
            "findings": findings
        }
