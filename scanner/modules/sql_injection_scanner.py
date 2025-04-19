import re
from urllib.parse import urljoin
from scanner.utils.http import fetch_url

class SQLInjectionScannerModule:
    def __init__(self):
        self.payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, NULL, NULL --",
            "' OR 1=1 --",
            "\" OR \"\" = \""
        ]
        self.error_signatures = [
            "SQL syntax.*MySQL",
            "Warning.*mysql_",
            "valid MySQL result",
            "check the manual that corresponds to your MySQL server version",
            "mysql_fetch_array()",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "pg_query()",
            "Warning.*pg_",
            "Microsoft OLE DB Provider for SQL Server",
            "SQLSTATE",
            "Syntax error in string in query expression",
            "Fatal error",
            "OperationalError"
        ]

    def run_test(self, domain, crawled_links):
        findings = {}

        # Only test links ending in .php
        php_links = [link for link in crawled_links if link.endswith(".php")]
        param_links = []

        # Crawl each .php page again to find links with parameters
        for link in php_links:
            response = fetch_url(link)
            if not response:
                continue

            found_links = re.findall(r'href=["\'](.*?\.php\?.*?)["\']', response.text, re.IGNORECASE)
            for found in found_links:
                full_url = urljoin(link, found)
                param_links.append(full_url)

        print(f"Param Links for SQLi: {param_links}")

        for link in param_links:
            for payload in self.payloads:
                test_url = self.inject_payload(link, payload)
                test_response = fetch_url(test_url)

                print(f"Testing URL: {test_url}")

                if not test_response:
                    continue

                # 1. Check for server errors (500/400)
                if test_response.status_code in [500, 400]:
                    findings[test_url] = f"Potential SQL Injection vulnerability! (HTTP {test_response.status_code})"
                    break

                # 2. Check for SQL error messages inside response body
                for signature in self.error_signatures:
                    if re.search(signature, test_response.text, re.IGNORECASE):
                        findings[test_url] = f"Potential SQL Injection vulnerability detected (signature: {signature})"
                        break

                if test_url in findings:
                    break

        if not findings:
            findings["Info"] = "No obvious SQL Injection vulnerabilities found."

        return {
            "module": "SQL Injection Scanner",
            "findings": findings
        }

    def inject_payload(self, url, payload):
        """
        Injects SQL payload into the first parameter.
        """
        if "?" not in url:
            return url

        base, params = url.split("?", 1)
        param_parts = params.split("&")
        first_param = param_parts[0].split("=")[0]

        # Inject payload into first param
        new_param = f"{first_param}={payload}"
        new_params = "&".join([new_param] + param_parts[1:])

        return f"{base}?{new_params}"
