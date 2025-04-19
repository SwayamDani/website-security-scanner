# scanner/modules/csrf_scanner.py

import re
from bs4 import BeautifulSoup
from scanner.utils.http import fetch_url

class CSRFScannerModule:
    def __init__(self):
        self.token_keywords = ["csrf", "token", "authenticity"]

    def run_test(self, domain, crawled_links):
        findings = {}

        for url in crawled_links:
            response = fetch_url(url)
            if not response or not response.text:
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                token_found = False
                inputs = form.find_all("input")

                for input_field in inputs:
                    name = input_field.get("name", "").lower()
                    id_attr = input_field.get("id", "").lower()
                    input_type = input_field.get("type", "").lower()

                    # Look for CSRF token in name or id
                    if any(keyword in name or keyword in id_attr for keyword in self.token_keywords):
                        token_found = True
                        break

                    # Extra: If it's a hidden input, check again
                    if input_type == "hidden" and any(keyword in name for keyword in self.token_keywords):
                        token_found = True
                        break

                method = form.get("method", "get").lower()

                # If no CSRF token or method is GET
                if not token_found:
                    if method == "post":
                        findings[url] = "Form likely missing CSRF token!"
                    elif method == "get":
                        findings[url] = "Form uses unsafe method=GET and likely missing CSRF protection!"

        if not findings:
            findings["Info"] = "No obvious CSRF vulnerabilities found."

        return {
            "module": "CSRF Token Scanner",
            "findings": findings
        }
