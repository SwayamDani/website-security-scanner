# scanner/modules/xss_scanner.py

import re
from urllib.parse import urljoin
from scanner.utils.http import fetch_url
from bs4 import BeautifulSoup

class XSSScannerModule:
    def __init__(self):
        self.payloads = [
            # Basic payloads
            "<script>alert(1)</script>",
            '"><svg onload=alert(1)>',
            "'\"><img src=x onerror=alert(1)>",
            
            # Filter bypass payloads
            "<img src=x onerror=alert(1) onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\">",
            "javascript:alert(1)",
            
            # DOM XSS specific payloads
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "');alert(1);//",
            
            # Encoded payloads
            "<script>eval(atob('YWxlcnQoMSk='))</script>",  # Base64 encoded alert
            "&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000049&#0000041",  # HTML encoding
        ]

    def extract_forms(self, url):
        """
        Extract all forms from a page.
        """
        forms = []
        response = fetch_url(url)
        if not response:
            return forms

        soup = BeautifulSoup(response.text, "html.parser")
        for form in soup.find_all("form"):
            details = {
                "action": form.attrs.get("action"),
                "method": form.attrs.get("method", "get"),
                "inputs": []
            }

            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_name = input_tag.attrs.get("name")
                input_type = input_tag.attrs.get("type", "text")
                input_value = input_tag.attrs.get("value", "")
                details["inputs"].append({
                    "name": input_name,
                    "type": input_type,
                    "value": input_value
                })

            forms.append(details)
        return forms

    def submit_form(self, base_url, form_details, payload):
        """
        Submits a form with the payload injected into all text fields.
        """
        action = form_details.get("action")
        method = form_details.get("method", "get").lower()
        inputs = form_details.get("inputs", [])

        target_url = urljoin(base_url, action)
        form_data = {}

        for input_tag in inputs:
            input_type = input_tag.get("type", "text")
            name = input_tag.get("name")

            if name:
                if input_type in ["text", "search", "email", "textarea", "password"]:
                    form_data[name] = payload
                else:
                    form_data[name] = input_tag.get("value", "test")  # Default value

        if method == "post":
            return fetch_url(target_url, method="POST", data=form_data)
        else:
            return fetch_url(target_url, method="GET", params=form_data)

    def run_test(self, domain, crawled_links):
        findings = {}

        # Step 1: Inject XSS payloads into all discovered forms
        for link in crawled_links:
            forms = self.extract_forms(link)
            if not forms:
                continue

            for form in forms:
                print(f"Submitting form at {link}")
                for payload in self.payloads:
                    self.submit_form(link, form, payload)

        # Step 2: Re-crawl all pages looking for any payload reflections
        for link in crawled_links:
            response = fetch_url(link)
            if not response:
                continue

            for payload in self.payloads:
                # Relaxed matching: check if payload or markers appear
                if payload in response.text:
                    findings[link] = "Stored XSS vulnerability detected!"

        if not findings:
            findings["Info"] = "No obvious reflected or stored XSS vulnerabilities found."

        return {
            "module": "XSS Scanner",
            "findings": findings
        }
