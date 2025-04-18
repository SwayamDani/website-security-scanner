# scanner/modules/headers.py

from scanner.utils.http import fetch_headers

class HTTPHeadersModule:
    def run_test(self, domain):
        headers = fetch_headers(domain)

        if headers is None:
            return {
                "module": "HTTP Headers",
                "error": "Failed to fetch headers"
            }

        important_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

        findings = {}

        for header in important_headers:
            findings[header] = headers.get(header, "Missing")

        return {
            "module": "HTTP Headers",
            "findings": findings
        }
