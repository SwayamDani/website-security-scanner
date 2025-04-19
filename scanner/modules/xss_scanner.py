from urllib.parse import urljoin
from bs4 import BeautifulSoup
from scanner.utils.http import fetch_url

class XSSScannerModule:
    def __init__(self):
        # Simple payloads to test
        self.payloads = [
            "<script>alert(1)</script>",
            '"><svg onload=alert(1)>',
            "'\"><img src=x onerror=alert(1)>"
        ]

    def run_test(self, domain, links=None):
        findings = {}

        if not links:
            return {
                "module": "XSS Scanner",
                "error": "No links to test"
            }

        for url in links:
            try:
                response = fetch_url(url)
                if response is None:
                    continue

                # Test Forms
                form_findings = self.test_forms(url)
                findings.update(form_findings)

                # Test URL parameters
                if "?" in url:
                    param_findings = self.test_url_params(url)
                    findings.update(param_findings)

            except Exception as e:
                findings[url] = f"Error testing: {str(e)}"

        if not findings:
            findings["Info"] = "No obvious reflected/form-based XSS vulnerabilities found."

        return {
            "module": "XSS Scanner",
            "findings": findings
        }

    def test_forms(self, url):
        """
        Detect forms, inject payloads, and check for reflected XSS in responses.
        """
        findings = {}

        response = fetch_url(url)
        if not response:
            return findings

        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        print(f"Forms found in {url}: {len(forms)}")

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()

            form_url = urljoin(url, action) if action else url

            inputs = form.find_all(["input", "textarea"])
            input_names = [input_.get("name") for input_ in inputs if input_.get("name")]

            if not input_names:
                continue

            for payload in self.payloads:
                data = {name: payload for name in input_names}

                if method == "post":
                    test_response = fetch_url(form_url, method="post", data=data)
                else:
                    params = "&".join([f"{name}={payload}" for name in input_names])
                    test_url = f"{form_url}?{params}"
                    test_response = fetch_url(test_url)

                print(f"Testing Form URL: {form_url} with method {method.upper()}")

                if test_response and payload in test_response.text:
                    findings[form_url] = "Potential form-based XSS vulnerability detected!"
                    break  # Stop if one payload triggers

        return findings

    def test_url_params(self, url):
        """
        Inject payload into GET parameters and check reflected response.
        """
        findings = {}

        base, params = url.split("?", 1)
        param_parts = params.split("&")

        for payload in self.payloads:
            new_params = "&".join([f"{param.split('=')[0]}={payload}" for param in param_parts])
            test_url = f"{base}?{new_params}"

            response = fetch_url(test_url)
            print(f"Testing Param URL: {test_url}")

            if response and payload in response.text:
                findings[test_url] = "Potential reflected XSS vulnerability detected!"
                break  # Stop if one payload triggers

        return findings
