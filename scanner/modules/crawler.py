import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class WebCrawlerModule:
    def __init__(self, max_pages=50):
        self.max_pages = max_pages
        self.visited = set()

    def run_test(self, domain):
        """
        Crawl the domain and collect internal links.
        """
        base_url = f"https://{domain}"
        to_visit = [base_url]
        findings = []

        while to_visit and len(self.visited) < self.max_pages:
            url = to_visit.pop()
            if url in self.visited:
                continue
            self.visited.add(url)

            try:
                response = requests.get(url, timeout=5)
                soup = BeautifulSoup(response.text, "html.parser")

                # Find all links on the page
                for link_tag in soup.find_all("a", href=True):
                    href = link_tag['href']
                    full_url = urljoin(base_url, href)
                    parsed = urlparse(full_url)

                    # Stay inside the same domain
                    if parsed.netloc == domain:
                        if full_url not in self.visited:
                            to_visit.append(full_url)

                findings.append(url)

            except Exception as e:
                # Skip pages that fail to load
                continue

        return {
            "module": "Web Crawler",
            "findings": {
                "Discovered Links": findings
            }
        }
