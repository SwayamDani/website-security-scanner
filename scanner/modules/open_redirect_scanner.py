import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from scanner.utils.http import fetch_url

class OpenRedirectScannerModule:
    def __init__(self):
        self.malicious_url = "https://evil.com"

    def run_test(self, domain, crawled_links):
        findings = {}

        # Step 1: Pick .php pages
        php_links = [link for link in crawled_links if link.endswith(".php")]

        param_links = []

        # Step 2: Crawl inside each .php page to find links with parameters
        for link in php_links:
            response = fetch_url(link)
            if not response:
                continue

            found_links = re.findall(r'href=["\'](.*?\.php\?.*?)["\']', response.text, re.IGNORECASE)
            for found in found_links:
                full_url = urljoin(link, found)
                param_links.append(full_url)

        print(f"Param Links for Open Redirect: {param_links}")

        # Step 3: Inject malicious URL into parameters
        for link in param_links:
            injected_link = self.inject_malicious_url(link)
            response = fetch_url(injected_link, allow_redirects=False)

            print(f"Testing URL: {injected_link}")

            if not response:
                continue

            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get("Location", "")
                if "evil.com" in location:
                    findings[injected_link] = "Potential Open Redirect vulnerability detected!"

        if not findings:
            findings["Info"] = "No obvious Open Redirect vulnerabilities found."

        return {
            "module": "Open Redirect Scanner",
            "findings": findings
        }

    def inject_malicious_url(self, url):
        """
        Replace all parameter values with the malicious URL
        """
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        new_query = {}
        for key in query:
            new_query[key] = self.malicious_url

        injected_query = urlencode(new_query, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{injected_query}"
